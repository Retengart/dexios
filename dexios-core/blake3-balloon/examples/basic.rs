//! Basic example of using blake3-balloon for password hashing

use blake3_balloon::{
    generate_salt, hash_password, hash_password_with_params, verify_password, Params, Version,
};

fn main() -> anyhow::Result<()> {
    // Example 1: Basic usage with default parameters
    println!("=== Basic Usage ===");
    let password = b"my secure password";
    let salt = generate_salt();
    
    // Hash the password
    let hash = hash_password(password, &salt, Version::V1)?;
    println!("Password hashed successfully");
    println!("Salt: {:?}", hex::encode(&salt));
    println!("Hash: {:?}", hex::encode(&hash));
    
    // Verify the password
    let is_valid = verify_password(password, &salt, &hash, Version::V1)?;
    println!("Password verification: {}", if is_valid { "✓ Valid" } else { "✗ Invalid" });
    
    // Try with wrong password
    let wrong_password = b"wrong password";
    let is_valid = verify_password(wrong_password, &salt, &hash, Version::V1)?;
    println!("Wrong password verification: {}", if is_valid { "✓ Valid" } else { "✗ Invalid" });
    
    println!();
    
    // Example 2: Custom parameters for different security requirements
    println!("=== Custom Parameters ===");
    
    // Low security (fast) - suitable for less sensitive data
    let low_params = Params::new(1024, 1, 1)?; // ~4MB, 1 iteration
    let low_hash = hash_password_with_params(password, &salt, low_params)?;
    println!("Low security hash: {}", hex::encode(&low_hash));
    
    // Medium security - balanced
    let medium_params = Params::new(16384, 2, 1)?; // ~64MB, 2 iterations  
    let medium_hash = hash_password_with_params(password, &salt, medium_params)?;
    println!("Medium security hash: {}", hex::encode(&medium_hash));
    
    // High security (slow) - for very sensitive data
    let high_params = Params::new(65536, 3, 1)?; // ~256MB, 3 iterations
    let high_hash = hash_password_with_params(password, &salt, high_params)?;
    println!("High security hash: {}", hex::encode(&high_hash));
    
    println!();
    
    // Example 3: Demonstrating that different parameters produce different hashes
    println!("=== Parameter Impact ===");
    println!("Same password and salt with different parameters produce different hashes:");
    println!("Low != Medium: {}", low_hash != medium_hash);
    println!("Medium != High: {}", medium_hash != high_hash);
    
    println!();
    
    // Example 4: Timing comparison
    println!("=== Performance Comparison ===");
    use std::time::Instant;
    
    let start = Instant::now();
    let _ = hash_password_with_params(password, &salt, low_params)?;
    println!("Low security: {:?}", start.elapsed());
    
    let start = Instant::now();
    let _ = hash_password_with_params(password, &salt, medium_params)?;
    println!("Medium security: {:?}", start.elapsed());
    
    let start = Instant::now();
    let _ = hash_password_with_params(password, &salt, high_params)?;
    println!("High security: {:?}", start.elapsed());
    
    Ok(())
}