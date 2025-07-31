//! Basic usage example for BLAKE3-Balloon password hashing
//! 
//! This example demonstrates the simple API for hashing and verifying passwords.

use blake3_balloon::{
    hash_password, verify_password, generate_salt, 
    salt_to_hex, salt_from_hex
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== BLAKE3-Balloon Basic Usage Example ===\n");

    // 1. Generate a random salt
    println!("1. Generating a random salt...");
    let salt = generate_salt();
    let salt_hex = salt_to_hex(&salt);
    println!("   Salt (hex): {}\n", salt_hex);

    // 2. Hash a password
    println!("2. Hashing a password...");
    let password = b"my-secure-password-123";
    let hash = hash_password(password, &salt)?;
    println!("   Password: {:?}", std::str::from_utf8(password).unwrap());
    println!("   Hash: {:02x?}\n", hash);

    // 3. Verify the password
    println!("3. Verifying the password...");
    let is_valid = verify_password(password, &salt, &hash)?;
    println!("   Valid: {}\n", is_valid);

    // 4. Try with wrong password
    println!("4. Trying with wrong password...");
    let wrong_password = b"wrong-password";
    let is_invalid = verify_password(wrong_password, &salt, &hash)?;
    println!("   Valid: {}\n", is_invalid);

    // 5. Demonstrate salt storage/loading
    println!("5. Demonstrating salt storage and loading...");
    let recovered_salt = salt_from_hex(&salt_hex)?;
    println!("   Original salt == Recovered salt: {}\n", salt == recovered_salt);

    // 6. Hash the same password with recovered salt
    println!("6. Hashing with recovered salt...");
    let hash2 = hash_password(password, &recovered_salt)?;
    println!("   Hash matches: {}\n", hash == hash2);

    println!("=== Example completed successfully! ===");
    Ok(())
}