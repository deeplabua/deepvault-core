//! Passwords, passphrases and PINs (PRD 02, 2.2), from the system CSPRNG (`Entropy`). Every
//! choice is uniform: random values that would bias a choice are drawn again, never folded
//! with `%`. Results live in buffers that are zeroed on drop; the entropy reported is what the
//! generator put in, not an estimate of the text.
//!
//! Passphrase words are the EFF large word list (7776 words, 12.9 bits each), © Electronic
//! Frontier Foundation, CC BY 3.0: <https://www.eff.org/dice>.

use std::sync::OnceLock;

use zeroize::Zeroizing;

use crate::entropy::Entropy;
use crate::error::{Result, VaultError};

const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const DIGITS: &str = "0123456789";
/// Symbols that every keyboard layout types and no site refuses in practice.
const SYMBOLS: &str = "!@#$%^&*-_=+?.";
/// Told apart badly in many fonts.
const SIMILAR: &str = "Il1O0o";

const WORDS_TEXT: &str = include_str!("wordlists/eff_large.txt");

fn words() -> &'static [&'static str] {
    static WORDS: OnceLock<Vec<&'static str>> = OnceLock::new();
    WORDS.get_or_init(|| WORDS_TEXT.lines().collect())
}

/// A random password.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PasswordOptions {
    /// 8 to 64.
    pub length: u32,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
    /// Leave out `I l 1 O 0 o`.
    pub avoid_similar: bool,
    /// No character more than once (the length may not exceed the alphabet).
    pub no_repeats: bool,
}

impl Default for PasswordOptions {
    fn default() -> Self {
        Self {
            length: 20,
            uppercase: true,
            digits: true,
            symbols: true,
            avoid_similar: false,
            no_repeats: false,
        }
    }
}

/// A passphrase of EFF words.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PassphraseOptions {
    /// 3 to 12; 6 for a master password.
    pub words: u32,
    pub separator: char,
    /// First letter of each word upper case.
    pub capitalize: bool,
    /// Two random digits as a last group.
    pub number: bool,
}

impl Default for PassphraseOptions {
    fn default() -> Self {
        Self { words: 6, separator: '-', capitalize: false, number: false }
    }
}

/// Generated text and the bits of randomness in it.
pub struct Generated {
    pub text: Zeroizing<String>,
    pub bits: f64,
}

pub fn password(entropy: &mut dyn Entropy, options: PasswordOptions) -> Result<Generated> {
    if !(8..=64).contains(&options.length) {
        return Err(VaultError::InvalidGeneratorOptions);
    }
    let keep = |set: &str| -> Vec<char> {
        set.chars().filter(|c| !(options.avoid_similar && SIMILAR.contains(*c))).collect()
    };
    let mut sets = vec![keep(LOWER)];
    if options.uppercase {
        sets.push(keep(UPPER));
    }
    if options.digits {
        sets.push(keep(DIGITS));
    }
    if options.symbols {
        sets.push(keep(SYMBOLS));
    }
    let alphabet: Vec<char> = sets.concat();
    let length = options.length as usize;
    if options.no_repeats && length > alphabet.len() {
        return Err(VaultError::InvalidGeneratorOptions);
    }

    // Draw until every chosen set appears: the result is uniform over the passwords that use
    // them all. With 8+ characters and at most 4 sets this takes few draws.
    let mut chars = Zeroizing::new(vec!['\0'; length]);
    loop {
        if options.no_repeats {
            // Each slot from the characters not used yet: uniform over the arrangements.
            let mut left = Zeroizing::new(alphabet.clone());
            for slot in chars.iter_mut() {
                let pick = uniform(entropy, left.len());
                *slot = left.swap_remove(pick);
            }
        } else {
            for slot in chars.iter_mut() {
                *slot = alphabet[uniform(entropy, alphabet.len())];
            }
        }
        if sets.iter().all(|set| chars.iter().any(|c| set.contains(c))) {
            break;
        }
    }
    let text = Zeroizing::new(chars.iter().collect::<String>());
    // Slightly above the true value (the all-sets rule removes a sliver): close enough to show.
    let n = alphabet.len() as f64;
    let bits = if options.no_repeats {
        (0..length).map(|i| (n - i as f64).log2()).sum()
    } else {
        length as f64 * n.log2()
    };
    Ok(Generated { text, bits })
}

pub fn passphrase(entropy: &mut dyn Entropy, options: PassphraseOptions) -> Result<Generated> {
    if !(3..=12).contains(&options.words) || options.separator.is_alphanumeric() {
        return Err(VaultError::InvalidGeneratorOptions);
    }
    let list = words();
    let mut text = Zeroizing::new(String::with_capacity(options.words as usize * 11 + 4));
    for index in 0..options.words {
        if index > 0 {
            text.push(options.separator);
        }
        let word = list[uniform(entropy, list.len())];
        if options.capitalize {
            let mut letters = word.chars();
            if let Some(first) = letters.next() {
                text.extend(first.to_uppercase());
                text.push_str(letters.as_str());
            }
        } else {
            text.push_str(word);
        }
    }
    let mut bits = f64::from(options.words) * (list.len() as f64).log2();
    if options.number {
        let number = uniform(entropy, 100);
        text.push(options.separator);
        text.push(char::from(b'0' + (number / 10) as u8));
        text.push(char::from(b'0' + (number % 10) as u8));
        bits += 100f64.log2();
    }
    Ok(Generated { text, bits })
}

pub fn pin(entropy: &mut dyn Entropy, length: u32) -> Result<Generated> {
    if !(4..=12).contains(&length) {
        return Err(VaultError::InvalidGeneratorOptions);
    }
    let mut text = Zeroizing::new(String::with_capacity(length as usize));
    for _ in 0..length {
        text.push(char::from(b'0' + uniform(entropy, 10) as u8));
    }
    Ok(Generated { text, bits: f64::from(length) * 10f64.log2() })
}

/// A uniform index below `bound` (at most 2^32): rejection sampling over 32-bit draws.
fn uniform(entropy: &mut dyn Entropy, bound: usize) -> usize {
    debug_assert!(bound > 0 && bound as u64 <= u64::from(u32::MAX) + 1);
    let bound = bound as u64;
    // The largest multiple of `bound` that fits in 2^32; draws at or above it are thrown away.
    let limit = (1u64 << 32) - ((1u64 << 32) % bound);
    loop {
        let mut bytes = [0u8; 4];
        entropy.fill(&mut bytes);
        let value = u64::from(u32::from_le_bytes(bytes));
        if value < limit {
            return (value % bound) as usize;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entropy::SystemEntropy;

    #[test]
    fn the_word_list_is_the_eff_large_list() {
        let list = words();
        assert_eq!(list.len(), 7776);
        assert_eq!((list[0], list[7775]), ("abacus", "zoom"));
        assert!(list.iter().all(|w| !w.is_empty() && w.chars().all(|c| c.is_ascii_lowercase() || c == '-')));
    }

    #[test]
    fn passwords_have_the_length_and_every_chosen_set() {
        let mut entropy = SystemEntropy;
        for _ in 0..200 {
            let generated =
                password(&mut entropy, PasswordOptions { length: 8, ..Default::default() }).unwrap();
            let text = generated.text.as_str();
            assert_eq!(text.chars().count(), 8);
            assert!(text.chars().any(|c| c.is_ascii_uppercase()));
            assert!(text.chars().any(|c| c.is_ascii_lowercase()));
            assert!(text.chars().any(|c| c.is_ascii_digit()));
            assert!(text.chars().any(|c| SYMBOLS.contains(c)));
        }
        let plain = PasswordOptions {
            length: 30,
            uppercase: false,
            digits: false,
            symbols: false,
            avoid_similar: true,
            no_repeats: false,
        };
        let text = password(&mut entropy, plain).unwrap().text;
        assert!(text.chars().all(|c| c.is_ascii_lowercase() && c != 'l' && c != 'o'));
    }

    #[test]
    fn no_repeats_means_every_character_once() {
        let mut entropy = SystemEntropy;
        let options = PasswordOptions { length: 40, no_repeats: true, ..Default::default() };
        for _ in 0..200 {
            let text = password(&mut entropy, options).unwrap().text;
            let mut chars: Vec<char> = text.chars().collect();
            chars.sort_unstable();
            chars.dedup();
            assert_eq!(chars.len(), 40);
        }
        // 26 lower-case letters cannot fill 30 places without a repeat.
        let too_long = PasswordOptions {
            length: 30,
            uppercase: false,
            digits: false,
            symbols: false,
            avoid_similar: false,
            no_repeats: true,
        };
        assert_eq!(password(&mut entropy, too_long).err(), Some(VaultError::InvalidGeneratorOptions));
        let bits =
            password(&mut entropy, PasswordOptions { length: 8, no_repeats: true, ..Default::default() })
                .unwrap()
                .bits;
        assert!((bits - (0..8).map(|i| (76.0 - f64::from(i)).log2()).sum::<f64>()).abs() < 1e-9);
    }

    #[test]
    fn bits_are_length_times_alphabet() {
        let mut entropy = SystemEntropy;
        // 26 + 26 + 10 + 14 = 76 symbols.
        let generated = password(&mut entropy, PasswordOptions::default()).unwrap();
        assert!((generated.bits - 20.0 * 76f64.log2()).abs() < 1e-9);
        let phrase =
            passphrase(&mut entropy, PassphraseOptions { number: true, ..Default::default() }).unwrap();
        assert!((phrase.bits - (6.0 * 7776f64.log2() + 100f64.log2())).abs() < 1e-9);
        assert!((pin(&mut entropy, 6).unwrap().bits - 6.0 * 10f64.log2()).abs() < 1e-9);
    }

    #[test]
    fn passphrases_are_words_from_the_list() {
        let mut entropy = SystemEntropy;
        let options = PassphraseOptions { words: 5, separator: '.', capitalize: true, number: true };
        let text = passphrase(&mut entropy, options).unwrap().text;
        let groups: Vec<&str> = text.split('.').collect();
        assert_eq!(groups.len(), 6);
        for word in &groups[..5] {
            assert!(word.chars().next().unwrap().is_ascii_uppercase());
            assert!(words().contains(&word.to_lowercase().as_str()));
        }
        assert!(groups[5].len() == 2 && groups[5].chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn out_of_range_options_are_refused() {
        let mut entropy = SystemEntropy;
        let short = PasswordOptions { length: 7, ..Default::default() };
        assert_eq!(password(&mut entropy, short).err(), Some(VaultError::InvalidGeneratorOptions));
        let letter = PassphraseOptions { separator: 'a', ..Default::default() };
        assert_eq!(passphrase(&mut entropy, letter).err(), Some(VaultError::InvalidGeneratorOptions));
        assert_eq!(pin(&mut entropy, 3).err(), Some(VaultError::InvalidGeneratorOptions));
    }

    /// Every symbol of a small alphabet comes up about equally often: a `%` without rejection
    /// would show here as a skew towards the first symbols. 26 lower-case letters, 520 000 draws.
    #[test]
    fn choices_are_uniform() {
        let mut entropy = SystemEntropy;
        let mut counts = [0u32; 26];
        for _ in 0..20_000 {
            let options = PasswordOptions {
                length: 26,
                uppercase: false,
                digits: false,
                symbols: false,
                avoid_similar: false,
                no_repeats: false,
            };
            for c in password(&mut entropy, options).unwrap().text.chars() {
                counts[(c as u8 - b'a') as usize] += 1;
            }
        }
        let expected = 20_000.0;
        // χ² with 25 degrees of freedom; above 52.6 happens by chance in 1 run out of 1000.
        let chi2: f64 = counts.iter().map(|&n| (f64::from(n) - expected).powi(2) / expected).sum();
        assert!(chi2 < 52.6, "χ² = {chi2}, counts = {counts:?}");
    }
}
