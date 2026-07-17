/**
 * Demo breach corpus: a slice of the most common passwords from public breach
 * analyses (rockyou / NCSC / SplashData top lists). Good enough to make the
 * health check real in dev; point VK_BREACH_CORPUS at a full dump (plaintext
 * or HIBP `HASH:COUNT` lines) or set VK_HIBP_UPSTREAM for production coverage.
 */
export const COMMON_PASSWORDS: string[] = [
  "123456", "password", "12345678", "qwerty", "123456789", "12345", "1234",
  "111111", "1234567", "dragon", "123123", "baseball", "abc123", "football",
  "monkey", "letmein", "696969", "shadow", "master", "666666", "qwertyuiop",
  "123321", "mustang", "1234567890", "michael", "654321", "superman", "1qaz2wsx",
  "7777777", "121212", "000000", "qazwsx", "123qwe", "killer", "trustno1",
  "jordan", "jennifer", "zxcvbnm", "asdfgh", "hunter", "buster", "soccer",
  "harley", "batman", "andrew", "tigger", "sunshine", "iloveyou", "2000",
  "charlie", "robert", "thomas", "hockey", "ranger", "daniel", "starwars",
  "klaster", "112233", "george", "computer", "michelle", "jessica", "pepper",
  "1111", "zxcvbn", "555555", "11111111", "131313", "freedom", "777777",
  "pass", "maggie", "159753", "aaaaaa", "ginger", "princess", "joshua",
  "cheese", "amanda", "summer", "love", "ashley", "nicole", "chelsea",
  "biteme", "matthew", "access", "yankees", "987654321", "dallas", "austin",
  "thunder", "taylor", "matrix", "mobilemail", "mom", "monitor", "monitoring",
  "montana", "moon", "moscow", "password1", "password123", "welcome",
  "welcome1", "admin", "root", "toor", "pass123", "abc12345", "letmein1",
  "qwerty123", "secret", "god", "sex", "money", "phoenix", "whatever",
  "cookie", "internet", "hello", "hello123", "changeme", "default",
  "passw0rd", "p@ssw0rd", "p@ssword", "test", "test123", "guest", "master1",
  "hunter2", "0", "iloveu", "lovely", "888888", "999999", "159357",
  "abcd1234", "asdf1234", "samsung", "a123456", "123abc", "azerty", "loveme",
  "flower", "hottie", "princess1", "chocolate", "family", "jesus", "purple",
  "angel", "friend", "dolphin", "vanessa", "butterfly", "rainbow", "spider",
];
