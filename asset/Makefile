setup:
	cargo install --git https://github.com/Nilay27/ever-assembler.git --branch p256-instructions
build:
	asm P256_CHKSIGNS/ValidSignature.code
	asm P256_CHKSIGNS/WrongPublicKey.code
	asm P256_CHKSIGNS/InvalidPublicKey.code
	asm P256_CHKSIGNS/InvalidSignatureLength.code
	asm P256_CHKSIGNS/SignatureUnderflow.code
	asm P256_CHKSIGNS/InvalidMessageType.code
	asm P256_CHKSIGNU/ValidSignature.code
	asm P256_CHKSIGNU/WrongPublicKey.code
	asm P256_CHKSIGNU/InvalidPublicKey.code
	asm P256_CHKSIGNU/InvalidSignatureLength.code
	asm P256_CHKSIGNU/SignatureUnderflow.code
	asm P256_CHKSIGNU/InvalidMessageType.code

