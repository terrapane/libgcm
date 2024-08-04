/*
 *  gcm.cpp
 *
 *  Copyright (C) 2024
 *  Terrapane Corporation
 *  All Rights Reserved
 *
 *  Author:
 *      Paul E. Jones <paulej@packetizer.com>
 *
 *  Description:
 *      This file implements the Galois Counter Mode (GCM) object that
 *      implements the logic defined in NIST Special Publication 800-38D.
 *
 *      The specification describes operations on bit strings.  For performance
 *      reasons, internally this implementation groups the bits into 32-bit
 *      words.  This reduces the number of bit shift and XOR operations
 *      required.
 *
 *  Portability Issues:
 *      None.
 */

#include <cstring>
#include <terra/crypto/cipher/gcm.h>
#include <terra/secutil/secure_erase.h>
#include "gcm_utilities.h"

namespace Terra::Crypto::Cipher
{

/*
 *  GCM::GCM()
 *
 *  Description:
 *      Constructor for the GCM object using the specified block cipher.
 *      The default block cipher is AES.
 *
 *  Parameters:
 *      cipher [in]
 *          The block cipher to utilize.
 *
 *  Returns:
 *      Nothing.
 *
 *  Comments:
 *      None.
 */
GCM::GCM(BlockCipher cipher) :
    finalized{false},
    final_text{false},
    counter{0}
{
    if (cipher != BlockCipher::AES)
    {
        throw GCMException("Unsupported block cipher specified");
    }
}

/*
 *  GCM::GCM()
 *
 *  Description:
 *      Constructor for the GCM object.
 *
 *  Parameters:
 *      iv [in]
 *          The initialization vector to use with this object.  The maximum
 *          length of this vector cannot exceed 2^64 - 1 octets.
 *
 *      key [in]
 *          The encryption key to use with this this object.  This must be
 *          any one of 16, 24, or 32 octets for AES.
 *
 *      cipher [in]
 *          The block cipher to utilize.  The default is AES.
 *
 *  Returns:
 *      Nothing.
 *
 *  Comments:
 *      None.
 */
GCM::GCM(const std::span<const std::uint8_t> iv,
         const std::span<const std::uint8_t> key,
         BlockCipher cipher) :
    GCM(cipher)
{
    // Set the encryption/decryption IV and key
    SetKey(iv, key);
}

/*
 *  GCM::GCM()
 *
 *  Description:
 *      Copy Constructor for the GCM object.
 *
 *  Parameters:
 *      other [in]
 *          The other GCM object from which to copy values.
 *
 *  Returns:
 *      Nothing.
 *
 *  Comments:
 *      None.
 */
GCM::GCM(const GCM &other) :
    finalized{other.finalized},
    final_text{other.final_text},
    counter{other.counter},
    aes{other.aes},
    H{other.H},
    Y0{other.Y0},
    Y{other.Y}
{
    // Does the other object have a GHASH object?
    if (other.ghash)
    {
        // Create GHASH object
        ghash = std::make_unique<GHASH>(H);

        // Copy the GHASH object
        *ghash = *other.ghash;
    }
}

/*
 *  GCM::GCM()
 *
 *  Description:
 *      Move Constructor for the GCM object.
 *
 *  Parameters:
 *      other [in]
 *          The other GCM object from which to move values.
 *
 *  Returns:
 *      Nothing.
 *
 *  Comments:
 *      None.
 */
GCM::GCM(GCM &&other) noexcept :
    finalized{other.finalized},
    final_text{other.final_text},
    counter{other.counter},
    aes{std::move(other.aes)},
    H{other.H},
    Y0{other.Y0},
    Y{other.Y},
    ghash{std::move(other.ghash)}
{
}

/*
 *  GCM::~GCM()
 *
 *  Description:
 *      Destructor for the GCM object.
 *
 *  Parameters:
 *      None.
 *
 *  Returns:
 *      Nothing.
 *
 *  Comments:
 *      None.
 */
GCM::~GCM()
{
    SecUtil::SecureErase(counter);
}

/*
 *  GCM::operator=()
 *
 *  Description:
 *      Assignment operator for the GCM object.
 *
 *  Parameters:
 *      other [in]
 *          The other GCM object from which to copy values.
 *
 *  Returns:
 *      A reference to this object.
 *
 *  Comments:
 *      None.
 */
GCM &GCM::operator=(const GCM &other)
{
    // Just return this object if "other" is the same as this object
    if (this == &other) return *this;

    // Copy important values from the other objects (ignoring temporaries)
    finalized = other.finalized;
    final_text = other.final_text;
    counter = other.counter;
    aes = other.aes;
    H = other.H;
    Y0 = other.Y0;
    Y = other.Y;

    // Reset the GHASH object
    ghash.reset();

    // If the other has a GHASH object, copy it
    if (other.ghash)
    {
        // Create GHASH object
        ghash = std::make_unique<GHASH>(H);

        // Copy the GHASH object
        *ghash = *other.ghash;
    }

    return *this;
}

/*
 *  GCM::SetKey()
 *
 *  Description:
 *      This function will set the IV and key to be used for GCM authenticated
 *      encryption.  If one wishes to re-use the same GCM object after
 *      finalizing the encryption / decryption work, calling this function will
 *      reset the object for re-use.
 *
 *  Parameters:
 *      iv [in]
 *          The initialization vector to use with this object.  The maximum
 *          length of this vector cannot exceed 2^64 - 1 octets.
 *
 *      key [in]
 *          The encryption key to use with this this object.  This must be
 *          any one of 16, 24, or 32 octets for AES.
 *
 *  Returns:
 *      Nothing, though an exception will be thrown if the key provided is not
 *      one of 16, 24, or 32 octets in length as required by the standard or
 *      if the initialization vector does not contain at least one octet.
 *
 *  Comments:
 *      None.
 */
void GCM::SetKey(const std::span<const std::uint8_t> iv,
                 const std::span<const std::uint8_t> key)
{
    // Reset the GHASH object, if one exists
    ghash.reset();

    // Ensure the IV length is acceptable
    if (iv.empty() || (iv.size() > Max_IV_Length))
    {
        throw GCMException("Invalid IV length given");
    }

    try
    {
        // Set the encryption key
        aes.SetKey(key);
    }
    catch(const AESException &e)
    {
        // Translate the GCM exception
        throw GCMException(e.what());
    }

    // Set the value of H to zero
    std::memset(H.data(), 0, H.size());

    // Assign H to E(K, 0^128)
    aes.Encrypt(H, H);

    // Assign the initial value of Y
    if (iv.size() == 12)
    {
        // Y0 = IV || 0^31 || 1
        std::memcpy(Y0.data(), iv.data(), iv.size());
        counter = 1;
        PutWord(counter, std::span<std::uint8_t,4>(Y0.data() + 12, 4));

        // Copy Y0 to Y
        Y = Y0;
    }
    else
    {
        // Compute the GHASH using (H, {}, iv) as input
        GHASH(H, {}, iv).Result(Y0);
        Y = Y0;

        // Read the initial counter value
        GetWord(std::span<const std::uint8_t, 4>(Y.data() + 12, 4), counter);
    }

    // Reset some internal variables
    finalized = false;
    final_text = false;

    // Create GHASH object
    ghash = std::make_unique<GHASH>(H);
}

/*
 *  GCM::InputAAD()
 *
 *  Description:
 *      Additional authenticated data (AAD) to be consumed by the GCM function.
 *      AAD, if any, MUST be provided to the GCM function before any calls
 *      are made to Encrypt() or Decrypt().
 *
 *  Parameters:
 *      aad [in]
 *          Additional authenticated data (AAD) to be provided as input.
 *          For best performance, the length of the span should be an
 *          integral number of 16 octets, with the exception of the last block.
 *          One may call this function multiple times to provide AAD
 *          incrementally.
 *
 *  Returns:
 *      Nothing.
 *
 *  Comments:
 *      The maximum length of AAD per the specification is 2^64 - 1 bits.
 */
void GCM::InputAAD(const std::span<const std::uint8_t> aad)
{
    // Ensure that the GCM object is properly keyed
    if (!ghash) throw GCMException("A key was not provided to GCM");

    // Pass the AAD to the GHASH object
    ghash->InputAAD(aad);
}

/*
 *  GCM::Encrypt()
 *
 *  Description:
 *      This function will encrypt the provided text.  GCM processes plaintext
 *      in blocks of 16 octets.  One must pass one or more 16-octet blocks
 *      per call.  Only the final call may contain fewer than 16 octets.
 *      It is permissible to pass all data to be encrypted by making a single
 *      call.  Precisely the same number of input plaintext octets will be
 *      returned as output ciphertext octets.
 *
 *  Parameters:
 *      plaintext [in]
 *          The octets to be encrypted.  This must contain one or more complete
 *          blocks (16 octets) with the exception that the final block may
 *          container fewer than 16 octets.  If a partial block (i.e., fewer
 *          than 16 octets) is observed, it is assumed to be the final block
 *          and no other input is accepted.
 *
 *      ciphertext [out]
 *          The encrypted octets.  This span of octets may refer to the same
 *          memory location as the plaintext, as encryption is performed
 *          in place.  The size of the span must be >= the size of the
 *          plaintext span.
 *
 *  Returns:
 *      A span over the same octets as the variable "ciphertext", but with
 *      the length set to the same length as "plaintext".
 *
 *  Comments:
 *      If calling Encrypt(), one should not call Decrypt() using the same GCM
 *      object unless the object is reset via a call to the SetKey() function.
 */
std::span<std::uint8_t> GCM::Encrypt(
    const std::span<const std::uint8_t> plaintext,
    std::span<std::uint8_t> ciphertext)
{
    // Ensure that the GCM object is properly keyed
    if (!ghash) throw GCMException("A key was not provided to GCM");

    // Ensure the GCM object does not believe the final text block was provided
    if (final_text) throw GCMException("Final input already received");

    // Ensure the object is not finalized
    if (finalized) throw GCMException("Cipher is already finalized");

    // Ensure the ciphertext parameter is large enough
    if (ciphertext.size() < plaintext.size())
    {
        throw GCMException("Ciphertext span is too short");
    }

    // How many octets remaining
    std::size_t remaining = plaintext.size();
    if (remaining == 0) return {ciphertext.data(), 0};

    // Pointers into the ciphertext and plaintext spans
    const std::uint8_t *p = plaintext.data();
    std::uint8_t *c = ciphertext.data();

    // Iterate over blocks of 16 octets at a time
    while (remaining >= 16)
    {
        // Increment Yi modulo 2^32
        PutWord(++counter, std::span<std::uint8_t, 4>(Y.data() + 12, 4));

        // Encrypt / E(K, Yi)
        aes.Encrypt(Y, T1);

        // Ci = Pi XOR E(K, Yi)
        GetWordArray(std::span<const std::uint8_t, 16>(p, 16), W1);
        GetWordArray(T1, W2);
        VectorXOR(W1, W2);
        PutWordArray(W1, std::span<std::uint8_t, 16>(c, 16));

        // Input the ciphertext into the GHASH object
        ghash->InputText(std::span<std::uint8_t, 16>(c, 16));

        // Increment / decrement values
        remaining -= 16;
        p += 16;
        c += 16;
    }

    // Is there a partial block?
    if (remaining > 0)
    {
        // Increment right-most 32-bits of Yi modulo 2^32
        PutWord(++counter, std::span<std::uint8_t, 4>(Y.data() + 12, 4));

        // Encrypt / E(K, Yi)
        aes.Encrypt(Y, T1);

        // Ci = Pi XOR E(K, Yi)
        std::memset(T2.data(), 0, T2.size());
        std::memcpy(T2.data(), p, remaining);
        GetWordArray(T1, W1);
        GetWordArray(T2, W2);
        VectorXOR(W1, W2);
        PutWordArray(W1, T2);
        std::memcpy(c, T2.data(), remaining);

        // Input the ciphertext into the GHASH object
        ghash->InputText(std::span<std::uint8_t>(c, remaining));

        // Having a partial block indicates the final text
        final_text = true;
    }

    return {ciphertext.data(), plaintext.size()};
}

/*
 *  GCM::Decrypt()
 *
 *  Description:
 *      This function will decrypt the provided text.  GCM processes ciphertext
 *      in blocks of 16 octets.  One must pass one or more 16-octet blocks
 *      per call.  Only the final call may contain fewer than 16 octets.
 *      It is permissible to pass all data to be decrypted by making a single
 *      call.  Precisely the same number of input ciphertext octets will be
 *      returned as output plaintext octets.
 *
 *  Parameters:
 *      ciphertext [in]
 *          The octets to be decrypted.  This must contain one or more complete
 *          blocks (16 octets) with the exception that the final block may
 *          container fewer than 16 octets.  If a partial block (i.e., fewer
 *          than 16 octets) is observed, it is assumed to be the final block
 *          and no other input is accepted.
 *
 *      plaintext [out]
 *          The decrypted octets.  This span of octets may refer to the same
 *          memory location as the plaintext, as encryption is performed
 *          in place.  The size of the span must be >= the size of the
 *          plaintext span.
 *
 *  Returns:
 *      A span over the same octets as the variable "plaintext", but with
 *      the length set to the same length as "ciphertext".
 *
 *  Comments:
 *      If calling Encrypt(), one should not call Decrypt() using the same GCM
 *      object unless the object is reset via a call to the SetKey() function.
 */
std::span<std::uint8_t> GCM::Decrypt(
    const std::span<const std::uint8_t> ciphertext,
    std::span<std::uint8_t> plaintext)
{
    // Ensure that the GCM object is properly keyed
    if (!ghash) throw GCMException("A key was not provided to GCM");

    // Ensure the GCM object does not believe the final text block was provided
    if (final_text) throw GCMException("Final input already received");

    // Ensure the object is not finalized
    if (finalized) throw GCMException("Cipher is already finalized");

    // Ensure the plaintext parameter is large enough
    if (plaintext.size() < ciphertext.size())
    {
        throw GCMException("Plaintext span is too short");
    }

    // How many octets remaining
    std::size_t remaining = ciphertext.size();
    if (remaining == 0) return {plaintext.data(), 0};

    // Pointers into the ciphertext and plaintext spans
    const std::uint8_t *c = ciphertext.data();
    std::uint8_t *p = plaintext.data();

    // Iterate over blocks of 16 octets at a time
    while (remaining >= 16)
    {
        // Increment Yi modulo 2^32
        PutWord(++counter, std::span<std::uint8_t, 4>(Y.data() + 12, 4));

        // Encrypt / E(K, Yi)
        aes.Encrypt(Y, T1);

        // Pi = Ci XOR E(K, Yi)
        GetWordArray(std::span<const std::uint8_t, 16>(c, 16), W1);
        GetWordArray(T1, W2);
        VectorXOR(W1, W2);
        PutWordArray(W1, std::span<std::uint8_t, 16>(p, 16));

        // Input the ciphertext into the GHASH object
        ghash->InputText(std::span<const std::uint8_t, 16>(c, 16));

        // Increment / decrement values
        remaining -= 16;
        p += 16;
        c += 16;
    }

    // Is there a partial block?
    if (remaining > 0)
    {
        // Increment right-most 32-bits of Yi modulo 2^32
        PutWord(++counter, std::span<std::uint8_t, 4>(Y.data() + 12, 4));

        // Encrypt / E(K, Yi)
        aes.Encrypt(Y, T1);

        // Pi = Ci XOR E(K, Yi)
        std::memset(T2.data(), 0, T2.size());
        std::memcpy(T2.data(), c, remaining);
        GetWordArray(T1, W1);
        GetWordArray(T2, W2);
        VectorXOR(W1, W2);
        PutWordArray(W1, T2);
        std::memcpy(p, T2.data(), remaining);

        // Input the ciphertext into the GHASH object
        ghash->InputText(std::span<const std::uint8_t>(c, remaining));

        // Having a partial block indicates the final text
        final_text = true;
    }

    return {plaintext.data(), ciphertext.size()};
}

/*
 *  GCM::FinalizeAndGetTag()
 *
 *  Description:
 *      This function will finalize the GCM object and retrieve the
 *      authentication tag computed by the GHASH function.  This function is
 *      called after encrypting plaintext.
 *
 *  Parameters:
 *      tag [out]
 *          The span of octets into which the authentication tag will be
 *          placed.  While the GCM specification allows for use of shorter
 *          tags, this function will return the complete 16-octet tag.
 *          If the application desires to use shorter tags, the right-most
 *          octets should be discarded.
 *
 *  Returns:
 *      Nothing, though the authentication tag will be placed in the output
 *      parameter "tag".
 *
 *  Comments:
 *      Calling this function more than once will result in an exception.
 */
void GCM::FinalizeAndGetTag(std::span<std::uint8_t, 16> tag)
{
    // Ensure that the GCM object is properly keyed
    if (!ghash) throw GCMException("A key was not provided to GCM");

    // Ensure the object is not finalized
    if (finalized) throw GCMException("Cipher is already finalized");

    // Ensure the tag size is of appropriate size
    if (tag.size() != 16)
    {
        throw GCMException("Authentication tag parameter is too short");
    }

    // Finalize the GHASH object
    ghash->Finalize();

    // Mark this object as finalized
    finalized = true;

    // Retrieve the hash result
    ghash->Result(T1);

    // Encrypt Y0 / E(K, Y0)
    aes.Encrypt(Y0, T2);

    // The tag is the hash result [T1] XOR E(K, Y0) [T2]
    GetWordArray(T1, W1);
    GetWordArray(T2, W2);
    VectorXOR(W1, W2);
    PutWordArray(W1, tag);
}

/*
 *  GCM::FinalizeAndVerifyTag()
 *
 *  Description:
 *      This function will finalize the GCM object and verify the
 *      authentication tag computed by the GHASH function matches the tag
 *      passed as a parameter up to the length of the given tag.  This function
 *      is called after decrypting ciphertext.
 *
 *  Parameters:
 *      tag [in]
 *          The span of octets to compare the GHASH tag value against.  This
 *          tag should be between 1 and 16 octets in size.  An exception will
 *          be thrown if the length is invalid.
 *
 *  Returns:
 *      True if the tag matches, false if not.
 *
 *  Comments:
 *      Calling this function more than once will result in an exception.
 */
bool GCM::FinalizeAndVerifyTag(const std::span<const std::uint8_t> tag)
{
    // Finalize the GCM object and put the tag into T1
    FinalizeAndGetTag(T1);

    // Ensure the tag size is of appropriate size
    if ((tag.size() > 16) || tag.empty())
    {
        throw GCMException("Authentication tag parameter size is invalid");
    }

    // Compare the octets of tag against T2 (the resulting tag)
    if (std::memcmp(T1.data(), tag.data(), tag.size()) != 0) return false;

    return true;
}

} // namespace Terra::Crypto::Cipher
