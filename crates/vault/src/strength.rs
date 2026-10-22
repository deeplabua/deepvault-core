//! A rough estimate of how hard a password is to guess (PRD 02, 1.1). Not zxcvbn: the
//! character pool times the length, with penalties for repeats, runs and well-known passwords.
//! In the core so a stored password can be rated without leaving it (`Vault::strength`).

/// Five levels; `Strong` is what a new vault requires (a hypothesis to revisit with data).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    VeryWeak,
    Weak,
    Fair,
    Strong,
    VeryStrong,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Strength {
    pub level: Level,
    /// Estimated entropy.
    pub bits: f64,
    /// In characters.
    pub length: u32,
}

const COMMON: &[&str] = &[
    "password",
    "password1",
    "password123",
    "passw0rd",
    "123456",
    "12345678",
    "123456789",
    "1234567890",
    "qwerty",
    "qwerty123",
    "qwertyuiop",
    "letmein",
    "iloveyou",
    "admin",
    "welcome",
    "monkey",
    "dragon",
    "football",
    "abc123",
    "111111",
    "000000",
    "sunshine",
    "princess",
    "master",
    "йцукен",
    "пароль",
    "qwerty12345",
    "1q2w3e4r",
    "1qaz2wsx",
];

pub fn estimate(password: &str) -> Strength {
    let bits = bits(password);
    let level = match bits {
        b if b < 28.0 => Level::VeryWeak,
        b if b < 40.0 => Level::Weak,
        b if b < 60.0 => Level::Fair,
        b if b < 80.0 => Level::Strong,
        _ => Level::VeryStrong,
    };
    Strength { level, bits, length: password.chars().count() as u32 }
}

fn bits(password: &str) -> f64 {
    let chars: Vec<char> = password.chars().collect();
    if chars.is_empty() || COMMON.contains(&password.to_lowercase().as_str()) {
        return 0.0;
    }
    let mut pool = 0u32;
    if chars.iter().any(|c| c.is_ascii_lowercase()) {
        pool += 26;
    }
    if chars.iter().any(|c| c.is_ascii_uppercase()) {
        pool += 26;
    }
    if chars.iter().any(|c| c.is_ascii_digit()) {
        pool += 10;
    }
    if chars.iter().any(|c| c.is_ascii() && !c.is_ascii_alphanumeric()) {
        pool += 33;
    }
    if chars.iter().any(|c| !c.is_ascii()) {
        pool += 100;
    }
    // Characters that add little: a repeat of the one before, or the next in a run
    // ("abcd", "4321").
    let mut effective = 1.0;
    for pair in chars.windows(2) {
        let step = pair[1] as i64 - pair[0] as i64;
        effective += if step.abs() <= 1 { 0.25 } else { 1.0 };
    }
    // Few distinct characters: "abababab".
    let mut distinct = chars.clone();
    distinct.sort_unstable();
    distinct.dedup();
    effective = f64::min(effective, distinct.len() as f64 * 2.0);
    effective * f64::from(pool).log2()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_common_and_repetitive_passwords_are_weak() {
        assert_eq!(estimate("").level, Level::VeryWeak);
        assert_eq!(estimate("password").level, Level::VeryWeak);
        assert!(estimate("Qwerty123").level < Level::Strong);
        assert!(estimate("aaaaaaaaaaaaaaaaaaaa").level < Level::Fair);
        assert!(estimate("abcdefghijklmnop").level < Level::Strong);
    }

    #[test]
    fn long_passphrases_and_mixed_passwords_are_strong() {
        assert!(estimate("correct horse battery staple").level >= Level::Strong);
        assert!(estimate("k7#Vq!2pLm9@xR").level >= Level::Strong);
        assert!(estimate("тихий-ранок-над-Дніпром").level >= Level::Strong);
        assert_eq!(estimate("тихий-ранок-над-Дніпром").length, 23);
    }
}
