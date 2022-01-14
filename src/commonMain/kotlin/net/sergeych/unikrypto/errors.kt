package net.sergeych.unikrypto

open class UnikryptoError(text: String,reason: Throwable?=null): Exception(text, reason)

class OperationNotSupported: UnikryptoError("operation not supported")

class InvalidPasswordError(text: String = "invalid password"): UnikryptoError(text)