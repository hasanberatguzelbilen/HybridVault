import math
import string


def calculate_entropy(password: str) -> float:
    """
    Calculate the estimated password entropy in bits.

    Formula:
        Entropy = password_length * log2(character_space)
    """

    if not password:
        return 0.0

    character_space = 0

    if any(char.islower() for char in password):
        character_space += 26

    if any(char.isupper() for char in password):
        character_space += 26

    if any(char.isdigit() for char in password):
        character_space += 10

    if any(char in string.punctuation for char in password):
        character_space += len(string.punctuation)

    if character_space == 0:
        return 0.0

    return len(password) * math.log2(character_space)


def evaluate_password(password: str) -> str:
    """
    Return a simple strength classification based on entropy.
    """

    entropy = calculate_entropy(password)

    if entropy < 40:
        return "Weak"
    elif entropy < 60:
        return "Moderate"
    elif entropy < 80:
        return "Strong"
    else:
        return "Very Strong"


if __name__ == "__main__":
    password = input("Enter a password: ")

    entropy = calculate_entropy(password)
    strength = evaluate_password(password)

    print(f"Entropy: {entropy:.2f} bits")
    print(f"Strength: {strength}")
