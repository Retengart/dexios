use anyhow::{Context, Result};
use std::io::{self, Write, stdin};

use crate::{
    global::states::{ForceMode, PasswordState},
    question, warn,
};

use core::protected::Protected;
use zeroize::Zeroizing;

// this handles user-interactivity, specifically getting a "yes" or "no" answer from the user
// it requires the question itself, if the default is true/false
// if force is enabled then it will just return the `default`
pub fn get_answer(prompt: &str, default: bool, force: ForceMode) -> Result<bool> {
    if force == ForceMode::Force {
        return Ok(true);
    }

    let switch = if default { "(Y/n)" } else { "(y/N)" };

    let answer_bool = loop {
        question!("{prompt} {switch}: ");
        io::stdout().flush().context("Unable to flush stdout")?;

        let mut answer = String::new();
        stdin()
            .read_line(&mut answer)
            .context("Unable to read from stdin")?;

        let answer_lowercase = answer.to_lowercase();
        let first_char = answer_lowercase
            .chars()
            .next()
            .context("Unable to get first character of your answer")?;
        break match first_char {
            '\n' | '\r' => default,
            'y' => true,
            'n' => false,
            _ => {
                warn!("Unrecognised answer - please try again");
                continue;
            }
        };
    };
    Ok(answer_bool)
}

// this checks if the file exists
// then it prompts the user if they'd like to overwrite a file (while showing the associated file name)
// if they have the force argument supplied, this will just assume true
// if force mode is true, avoid prompts at all
pub fn overwrite_check(name: &str, force: ForceMode) -> Result<bool> {
    let answer = if std::fs::metadata(name).is_ok() {
        let prompt = format!("{name} already exists, would you like to overwrite?");
        get_answer(&prompt, true, force)?
    } else {
        true
    };
    Ok(answer)
}

fn read_zeroizing_password<F>(prompt: &str, prompt_password: &mut F) -> Result<Zeroizing<String>>
where
    F: FnMut(&str) -> Result<String>,
{
    prompt_password(prompt)
        .map(Zeroizing::new)
        .context("Unable to read password")
}

fn protected_from_zeroizing_string(input: &Zeroizing<String>) -> Protected<Vec<u8>> {
    Protected::new(input.as_bytes().to_vec())
}

fn get_password_with_prompt<F>(
    pass_state: &PasswordState,
    mut prompt_password: F,
) -> Result<Protected<Vec<u8>>>
where
    F: FnMut(&str) -> Result<String>,
{
    loop {
        let input = read_zeroizing_password("Password: ", &mut prompt_password)?;
        if pass_state == &PasswordState::Direct {
            return Ok(protected_from_zeroizing_string(&input));
        }

        let input_validation = read_zeroizing_password("Confirm password: ", &mut prompt_password)?;

        if input.as_str() == input_validation.as_str() && !input.is_empty() {
            return Ok(protected_from_zeroizing_string(&input));
        } else if input.is_empty() {
            warn!("Password cannot be empty, please try again.");
        } else {
            warn!("The passwords aren't the same, please try again.");
        }
    }
}

pub fn get_password(pass_state: &PasswordState) -> Result<Protected<Vec<u8>>> {
    get_password_with_prompt(pass_state, |prompt| {
        rpassword::prompt_password(prompt).map_err(Into::into)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;
    use std::collections::VecDeque;

    struct PromptScript {
        prompts: Vec<String>,
        answers: VecDeque<Result<String>>,
    }

    impl PromptScript {
        fn new(answers: Vec<Result<String>>) -> Self {
            Self {
                prompts: Vec::new(),
                answers: VecDeque::from(answers),
            }
        }

        fn prompt(&mut self, prompt: &str) -> Result<String> {
            self.prompts.push(prompt.to_owned());
            self.answers
                .pop_front()
                .expect("test prompt script should provide enough answers")
        }
    }

    #[test]
    fn direct_prompt_returns_protected_key() {
        let mut script = PromptScript::new(vec![Ok("direct secret".to_owned())]);

        let key = get_password_with_prompt(&PasswordState::Direct, |prompt| script.prompt(prompt))
            .expect("direct prompt should return a protected key");

        assert_eq!(
            script.prompts,
            ["Password: "],
            "direct mode should not ask for confirmation"
        );
        assert!(key.with_exposed(|key| key == b"direct secret"));
    }

    #[test]
    fn validate_prompt_accepts_matching_confirmation() {
        let mut script = PromptScript::new(vec![
            Ok("confirmed secret".to_owned()),
            Ok("confirmed secret".to_owned()),
        ]);

        let key =
            get_password_with_prompt(&PasswordState::Validate, |prompt| script.prompt(prompt))
                .expect("matching confirmation should return a protected key");

        assert_eq!(script.prompts, ["Password: ", "Confirm password: "]);
        assert!(key.with_exposed(|key| key == b"confirmed secret"));
    }

    #[test]
    fn validate_prompt_retries_after_mismatch() {
        let mut script = PromptScript::new(vec![
            Ok("first secret".to_owned()),
            Ok("different secret".to_owned()),
            Ok("matched secret".to_owned()),
            Ok("matched secret".to_owned()),
        ]);

        let key =
            get_password_with_prompt(&PasswordState::Validate, |prompt| script.prompt(prompt))
                .expect("mismatch should retry until confirmation matches");

        assert_eq!(
            script.prompts,
            [
                "Password: ",
                "Confirm password: ",
                "Password: ",
                "Confirm password: "
            ]
        );
        assert!(key.with_exposed(|key| key == b"matched secret"));
    }

    #[test]
    fn validate_prompt_retries_after_empty_input() {
        let mut script = PromptScript::new(vec![
            Ok(String::new()),
            Ok(String::new()),
            Ok("nonempty secret".to_owned()),
            Ok("nonempty secret".to_owned()),
        ]);

        let key =
            get_password_with_prompt(&PasswordState::Validate, |prompt| script.prompt(prompt))
                .expect("empty password should retry until non-empty confirmation matches");

        assert_eq!(
            script.prompts,
            [
                "Password: ",
                "Confirm password: ",
                "Password: ",
                "Confirm password: "
            ]
        );
        assert!(key.with_exposed(|key| key == b"nonempty secret"));
    }

    #[test]
    fn prompt_errors_do_not_format_entered_secret() {
        let entered_secret = "entered secret should stay out of errors";
        let mut script = PromptScript::new(vec![
            Ok(entered_secret.to_owned()),
            Err(anyhow!("prompt backend failed")),
        ]);

        let err =
            get_password_with_prompt(&PasswordState::Validate, |prompt| script.prompt(prompt))
                .expect_err("confirmation prompt failure should be returned");
        let formatted = format!("{err:#}");

        assert!(!formatted.contains(entered_secret));
        assert!(formatted.contains("Unable to read password"));
    }
}
