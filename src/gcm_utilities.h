/*
 *  gcm_utilities.h
 *
 *  Copyright (C) 2024
 *  Terrapane Corporation
 *  All Rights Reserved
 *
 *  Author:
 *      Paul E. Jones <paulej@packetizer.com>
 *
 *  Description:
 *      This file defines utility functions utilized by the Galois Counter Mode
 *      (GCM) and GCM Hash (GHASH) functions.
 *
 *  Portability Issues:
 *      None.
 */

#include <span>
#include <cstdint>

namespace Terra::Crypto::Cipher
{

/*
 *  VectorXOR()
 *
 *  Description:
 *      Perform an XOR operation over the vectors X and Y with the result
 *      stored in X.
 *
 *  Parameters:
 *      X [in/out]
 *          First vector to use in XOR operation.
 *
 *      Y [in]
 *          First vector to use in XOR operation.
 *
 *  Returns:
 *      Nothing, though the output will be placed in X.
 *
 *  Comments:
 *      None.
 */
constexpr void VectorXOR(std::span<std::uint32_t, 4> X,
                         const std::span<const std::uint32_t, 4> Y)
{
    X[0] ^= Y[0];
    X[1] ^= Y[1];
    X[2] ^= Y[2];
    X[3] ^= Y[3];
}

/*
 *  VectorRightShift()
 *
 *  Description:
 *      Shift the given vector one bit to the right.
 *
 *  Parameters:
 *      X [in/out]
 *          Vector that should be shifted to the right by one bit.
 *
 *  Returns:
 *      Nothing, though the parameter X will updated.
 *
 *  Comments:
 *      None.
 */
constexpr void VectorRightShift(std::span<std::uint32_t, 4> X)
{
    X[3] = (X[3] >> 1) | ((X[2] << 31) & 0x80000000);
    X[2] = (X[2] >> 1) | ((X[1] << 31) & 0x80000000);
    X[1] = (X[1] >> 1) | ((X[0] << 31) & 0x80000000);
    X[0] = (X[0] >> 1);
}

/*
 *  GetWordArray()
 *
 *  Description:
 *      This function will convert a 16-octet vector into an array of four
 *      32-bit words.
 *
 *  Parameters:
 *      octets [in]
 *          Octet array from which to read values to be placed into the word
 *          array.
 *
 *       words [out]
 *          The word array into which the octets are placed.
 *
 *  Returns:
 *      Nothing.
 *
 *  Comments:
 *      None.
 */
constexpr void GetWordArray(const std::span<const std::uint8_t, 16> octets,
                            std::span<std::uint32_t, 4> words)
{
    words[0] = ((static_cast<std::uint32_t>(octets[ 0]) << 24)) |
               ((static_cast<std::uint32_t>(octets[ 1]) << 16)) |
               ((static_cast<std::uint32_t>(octets[ 2]) <<  8)) |
               ((static_cast<std::uint32_t>(octets[ 3])      ));
    words[1] = ((static_cast<std::uint32_t>(octets[ 4]) << 24)) |
               ((static_cast<std::uint32_t>(octets[ 5]) << 16)) |
               ((static_cast<std::uint32_t>(octets[ 6]) <<  8)) |
               ((static_cast<std::uint32_t>(octets[ 7])      ));
    words[2] = ((static_cast<std::uint32_t>(octets[ 8]) << 24)) |
               ((static_cast<std::uint32_t>(octets[ 9]) << 16)) |
               ((static_cast<std::uint32_t>(octets[10]) <<  8)) |
               ((static_cast<std::uint32_t>(octets[11])      ));
    words[3] = ((static_cast<std::uint32_t>(octets[12]) << 24)) |
               ((static_cast<std::uint32_t>(octets[13]) << 16)) |
               ((static_cast<std::uint32_t>(octets[14]) <<  8)) |
               ((static_cast<std::uint32_t>(octets[15])      ));
}

/*
 *  GetWordArray()
 *
 *  Description:
 *      This function will convert a 4-octet vector into a single 32-bit word.
 *
 *  Parameters:
 *      octets [in]
 *          Octet array from which to read values to be placed into the word
 *          array.
 *
 *       word [out]
 *          The 32-bit word into which the octets are placed.
 *
 *  Returns:
 *      Nothing.
 *
 *  Comments:
 *      None.
 */
constexpr void GetWord(const std::span<const std::uint8_t, 4> octets,
                       std::uint32_t &word)
{
    word = ((static_cast<std::uint32_t>(octets[ 0]) << 24)) |
           ((static_cast<std::uint32_t>(octets[ 1]) << 16)) |
           ((static_cast<std::uint32_t>(octets[ 2]) <<  8)) |
           ((static_cast<std::uint32_t>(octets[ 3])      ));
}

/*
 *  PutWordArray()
 *
 *  Description:
 *      This function will convert a 32-bit word array holding four words
 *      into an octet vector.
 *
 *  Parameters:
 *      words [in]
 *          The word array from which to read values.
 *
 *      octets [out]
 *          Octet array into which values from the word array are written.
 *
 *  Returns:
 *      Nothing.
 *
 *  Comments:
 *      None.
 */
constexpr void PutWordArray(const std::span<const std::uint32_t, 4> words,
                            std::span<std::uint8_t, 16> octets)
{
    octets[ 0] = (words[0] >> 24) & 0xff;
    octets[ 1] = (words[0] >> 16) & 0xff;
    octets[ 2] = (words[0] >>  8) & 0xff;
    octets[ 3] = (words[0]      ) & 0xff;
    octets[ 4] = (words[1] >> 24) & 0xff;
    octets[ 5] = (words[1] >> 16) & 0xff;
    octets[ 6] = (words[1] >>  8) & 0xff;
    octets[ 7] = (words[1]      ) & 0xff;
    octets[ 8] = (words[2] >> 24) & 0xff;
    octets[ 9] = (words[2] >> 16) & 0xff;
    octets[10] = (words[2] >>  8) & 0xff;
    octets[11] = (words[2]      ) & 0xff;
    octets[12] = (words[3] >> 24) & 0xff;
    octets[13] = (words[3] >> 16) & 0xff;
    octets[14] = (words[3] >>  8) & 0xff;
    octets[15] = (words[3]      ) & 0xff;
}

/*
 *  PutWord()
 *
 *  Description:
 *      This function will convert a 32-bit word into a four-octet vector.
 *
 *  Parameters:
 *      word [in]
 *          The 32-bit word from which octets are extracted.
 *
 *      octets [out]
 *          Octet array into which values from the 32-bit word are written.
 *
 *  Returns:
 *      Nothing.
 *
 *  Comments:
 *      None.
 */
constexpr void PutWord(const std::uint32_t word,
                       std::span<std::uint8_t, 4> octets)
{
    octets[0] = (word >> 24) & 0xff;
    octets[1] = (word >> 16) & 0xff;
    octets[2] = (word >>  8) & 0xff;
    octets[3] = (word      ) & 0xff;
}

} // namespace Terra::Crypto::Cipher
