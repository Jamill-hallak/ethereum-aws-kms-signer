
# Ethereum AWS KMS Signer

A Go utility to sign Ethereum messages using AWS KMS, with support for message hashing and ECDSA signature adjustments according to Ethereum standards.

## Features

- Retrieve public keys from AWS KMS and convert them to Ethereum addresses.
- Generate Ethereum-compatible message hashes.
- Sign messages using AWS KMS.
- Adjust ECDSA signatures to meet Ethereum standards.

## Prerequisites

- Go 1.16+
- AWS SDK for Go
- AWS KMS setup with a suitable key
- Environment variables for AWS configuration

## Installation

1. Clone the repository:

    \`\`\`
    git clone https://github.com/Jamill-hallak/ethereum-aws-kms-signer.git
    cd ethereum-aws-kms-signer
    \`\`\`

2. Install dependencies:

    \`\`\`
    go mod tidy
    \`\`\`

## Configuration

Create a `.env` file in the root directory with the following content:

\`\`\`
AWS_REGION=<your-aws-region>
AWS_KMS_KEY_ID=<your-kms-key-id>
AWS_ACCESS_KEY_ID=<your-access-key-id>
AWS_SECRET_ACCESS_KEY=<your-secret-access-key>
\`\`\`

## Usage

### Running the Application

\`\`\`
go run main.go
\`\`\`

### Example Output

\`\`\`
Authorized Signer Address: 0xYourSignerAddress
Message Hash: 0xYourMessageHash
EthSignedMessage Hash: 0xYourEthSignedMessageHash
Signature: 0xYourSignature
\`\`\`

## Code Overview


### main.go

The entry point of the application. It loads environment variables, retrieves the public key from AWS KMS, generates message hashes, and signs the message.

### aws/kms.go

Contains the function to initialize the AWS KMS client using credentials from environment variables.

### aws/kms_utils.go

Contains utility functions related to AWS KMS operations, such as retrieving public keys and signing messages.

### ethereum/eth_utils.go

Contains utility functions related to Ethereum operations, such as generating message hashes and converting public keys to Ethereum addresses.

### ethereum/eth_signer.go

Handles Ethereum signature adjustments to conform to Ethereum's standards, including adjusting the S value and determining the recovery ID.

## Contributing

Feel free to submit issues, fork the repository, and send pull requests. We welcome all contributions!

## License

This project is licensed under the MIT License.
