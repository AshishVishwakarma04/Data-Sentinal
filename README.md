# Data-Sentinal

## Description

This project aims to prevent data breaches in organizations by providing an encryption and decryption mechanism for important files, as well as implementing security measures to capture unauthorized access attempts. The project is built using Python, Flask framework, and cryptographic algorithms.


Data breaches can lead to severe consequences, both for individuals and organizations. Here are a few real-life examples to demonstrate the significance of preventing data breaches:

1. **Financial Data Breach**: A cybercriminal gains unauthorized access to a company's financial records, compromising sensitive information such as credit card details, social security numbers, or banking credentials. This breach can result in financial loss, identity theft, and reputational damage for the organization and its customers.

2. **Healthcare Data Breach**: Attackers target healthcare institutions, gaining access to patient records containing personal health information (PHI). This breach exposes patients' confidential medical history, leading to potential privacy violations, insurance fraud, or even blackmail.

3. **Intellectual Property Theft**: Hackers infiltrate an organization's network, exfiltrating valuable intellectual property, trade secrets, or proprietary algorithms. Such breaches can have detrimental effects on an organization's competitive advantage, market position, and research investments.



## Working 

File Encryption and Decryption:

- Authorized users can upload important files to the web server.
The project employs cryptographic algorithms to encrypt the uploaded files, making them unreadable to unauthorized users.
Encrypted files are stored securely on the server.
When required, authorized users can decrypt the files using the web server interface, making them usable again.
User Authentication:

- The project implements a user authentication system to ensure only authorized users can access the encryption and decryption functionality.
Users are required to register an account or use existing credentials to log in to the web server interface.
Unauthorized access attempts are prevented by enforcing login authentication.
Unauthorized Access Detection:

- When an unauthorized user attempts to log in with incorrect credentials, the system captures their picture using the device's camera.
The timestamp of the attempt, along with the IP address of the attacker, is logged for further analysis.
This detection mechanism helps identify potential security threats and provides evidence for forensic analysis.
Web Server Interface:

- The project provides a user-friendly web interface for managing files, encryption, and decryption.
Users can easily navigate the interface to upload files, initiate encryption or decryption operations, and view their encrypted files.
The interface also displays log entries and captured images from unauthorized access attempts, providing visibility into security events.
Preventing Data Breaches:

- By encrypting important files, the project ensures that even if a device is hacked, the encrypted files remain secure and unreadable.
Unauthorized users are deterred from accessing sensitive information due to the robust encryption mechanism.
The combination of user authentication, unauthorized access detection, and encryption measures helps prevent data breaches and maintain data confidentiality.


## Features

- File Encryption: Encrypts important files (such as images, documents, and text files) to protect them from unauthorized access.
- File Decryption: Allows authorized users to decrypt the encrypted files anytime and from anywhere through a web server interface.
- Unauthorized Access Detection: Captures the timestamp, IP address, and a picture of the attacker when incorrect login attempts are made.
- User Authentication: Implements a login system to ensure only authorized users can access the encryption/decryption functionality.
- Web Server Interface: Provides a user-friendly web interface for managing files, encryption, and decryption.

## Tech Stack

- Flask - Web framework used in the project.
- OpenCV - Library used for capturing images from the camera.
- Fernet - Cryptographic algorithm used for file encryption and decryption.
