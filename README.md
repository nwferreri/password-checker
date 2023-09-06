# Password Checker

Uses the [Have I been pwned? Password Checker](https://haveibeenpwned.com/Passwords) API to check if a password has been involved in a data breach.

The API uses a [k-Anonimity model](https://haveibeenpwned.com/API/v3#SearchingPwnedPasswordsByRange) to search for passwords by partial hashes.

The user runs this script from the command line by inputting the passwords they would like to check. The script will hash those passwords, run them through the API, and return how many times each password was found in a data breach.
