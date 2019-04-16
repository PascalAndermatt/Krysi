package ch.fhnw.krysi;

import com.google.common.collect.BiMap;
import com.google.common.collect.HashBiMap;

import java.util.HashMap;
import java.util.Map;

public class SubstitutionPermutationNetwork {

    private final int rounds = 4;
    private final int numberOfBitsPerBlock = 4;
    private final int numberOfBlocks = 4;
//    private final byte[] key = {0b0000_0001, 0b0000_0001, 0b0000_0010, 0b0000_1000, 0b0000_1000, 0b0000_1100, 0b0000_0000, 0b0000_0000}; // für Tests
    private final byte[] key = {0b0000_0011, 0b0000_1010, 0b0000_1001, 0b0000_0100, 0b0000_1101, 0b0000_0110, 0b0000_0011, 0b0000_1111};
    private final int numberOfKeyBits = 32;

    private Map<Integer, byte[]> roundKeys = new HashMap<>();
    private Map<Integer, byte[]> roundKeysForDecrypt = new HashMap<>();
    private BiMap<Byte, Byte> sBox = HashBiMap.create();
    private Map<Integer, Integer> bitpermutation = new HashMap<>();
    public BiMap<Byte, String> binaryNumbers = HashBiMap.create();


    public SubstitutionPermutationNetwork(){
        createSBox();
        createBitpermutation();
        createBinaryNumbers();
        createRoundKeys();
        createRoundKeysForDecryption();
    }

    public Map<Integer, byte[]> getRoundKeys(){
        return this.roundKeys;
    }

    public Map<Integer, byte[]> getRoundKeysForDecrypt(){
        return this.roundKeysForDecrypt;
    }

    private void createSBox(){
        this.sBox.put((byte)0, (byte)14);
        this.sBox.put((byte)1, (byte)4);
        this.sBox.put((byte)2, (byte)13);
        this.sBox.put((byte)3, (byte)1);
        this.sBox.put((byte)4, (byte)2);
        this.sBox.put((byte)5, (byte)15);
        this.sBox.put((byte)6, (byte)11);
        this.sBox.put((byte)7, (byte)8);
        this.sBox.put((byte)8, (byte)3);
        this.sBox.put((byte)9, (byte)10);
        this.sBox.put((byte)10, (byte)6);
        this.sBox.put((byte)11, (byte)12);
        this.sBox.put((byte)12, (byte)5);
        this.sBox.put((byte)13, (byte)9);
        this.sBox.put((byte)14, (byte)0);
        this.sBox.put((byte)15, (byte)7);
    }

    private void createBitpermutation() {
        this.bitpermutation.put(0, 0);
        this.bitpermutation.put(1, 4);
        this.bitpermutation.put(2, 8);
        this.bitpermutation.put(3, 12);
        this.bitpermutation.put(4, 1);
        this.bitpermutation.put(5, 5);
        this.bitpermutation.put(6, 9);
        this.bitpermutation.put(7, 13);
        this.bitpermutation.put(8, 2);
        this.bitpermutation.put(9, 6);
        this.bitpermutation.put(10, 10);
        this.bitpermutation.put(11, 14);
        this.bitpermutation.put(12, 3);
        this.bitpermutation.put(13, 7);
        this.bitpermutation.put(14, 11);
        this.bitpermutation.put(15, 15);
    }

    private void createBinaryNumbers(){
        this.binaryNumbers.put((byte)0, "0000");
        this.binaryNumbers.put((byte)1, "0001");
        this.binaryNumbers.put((byte)2, "0010");
        this.binaryNumbers.put((byte)3, "0011");
        this.binaryNumbers.put((byte)4, "0100");
        this.binaryNumbers.put((byte)5, "0101");
        this.binaryNumbers.put((byte)6, "0110");
        this.binaryNumbers.put((byte)7, "0111");
        this.binaryNumbers.put((byte)8, "1000");
        this.binaryNumbers.put((byte)9, "1001");
        this.binaryNumbers.put((byte)10, "1010");
        this.binaryNumbers.put((byte)11, "1011");
        this.binaryNumbers.put((byte)12, "1100");
        this.binaryNumbers.put((byte)13, "1101");
        this.binaryNumbers.put((byte)14, "1110");
        this.binaryNumbers.put((byte)15, "1111");
    }

    public void createRoundKeys(){
        for (int i = 0; i <= rounds; i++){

            byte[] roundKey = new byte[4];

            for (int j = 0; j < 4; j++){
                roundKey[j] = key[i + j];
            }

            roundKeys.put(i, roundKey);
        }
    }

    public void createRoundKeysForDecryption(){
        this.roundKeysForDecrypt.put(0, this.roundKeys.get(this.rounds - 0));

        for (int i = 1; i < this.rounds; i++){
            this.roundKeysForDecrypt.put(i, this.makeBitpermutation(this.getRoundKeys().get(this.rounds - i)));
        }

        this.roundKeysForDecrypt.put(rounds, this.roundKeys.get(rounds - rounds));
    }

    public byte[] encrypt(byte[] randomBitString){
        byte[] result;
        result = initialWhiteStep(randomBitString);

        for (int i = 1; i < this.rounds; i++){
            result = normalRoundStep(result, i);
        }

        result = finalShortRound(result);

        return result;
    }

    public byte[] decrypt(byte[] encryptedString){
        byte[] result;
        result = initialWhiteStepInverse(encryptedString);

        for (int i = 1; i < this.rounds; i++){
            result = normalRoundStepInverse(result, i);
        }

        result = finalShortRoundInverse(result);

        return result;
    }

    private byte[] finalShortRoundInverse(byte[] bitBlocks) {
        byte[] result;
        result = substitutionWithSboxInverse(bitBlocks);

        return roundKeyAdditionInverse(result, this.rounds);
    }

    private byte[] normalRoundStepInverse(byte[] bitBlocks, int round) {
        byte[] result;

        result = substitutionWithSboxInverse(bitBlocks);
        result = makeBitpermutation(result);
        result = roundKeyAdditionInverse(result, round);

        return result;
    }

    public byte[] initialWhiteStep(byte[] randomBitString) {
        return roundKeyAddition(randomBitString, 0);
    }

    public byte[] initialWhiteStepInverse(byte[] randomBitString) {
        return roundKeyAdditionInverse(randomBitString, 0);
    }

    private byte[] normalRoundStep(byte[] bitBlocks, int round) {
        byte[] result;

        result = substitutionWithSbox(bitBlocks);
        result = makeBitpermutation(result);
        result = roundKeyAddition(result, round);

        return result;
    }

    private byte[] roundKeyAddition(byte[] bitBlocks, int round){
        byte[] result = new byte[4];

        for(int i = 0; i < bitBlocks.length; i++){
            result[i] = (byte) (bitBlocks[i] ^ roundKeys.get(round)[i]);
        }

        return result;
    }

    private byte[] roundKeyAdditionInverse(byte[] bitBlocks, int round){
        byte[] result = new byte[4];

        for(int i = 0; i < bitBlocks.length; i++){
            result[i] = (byte) (bitBlocks[i] ^ roundKeysForDecrypt.get(round)[i]);
        }

        return result;
    }

    private byte[] substitutionWithSbox(byte[] bitBlocks){
        byte[] result = new byte[bitBlocks.length];

        for (int i = 0; i < bitBlocks.length; i++){
            result[i] = this.sBox.get(bitBlocks[i]);
        }
        return result;
    }

    private byte[] substitutionWithSboxInverse(byte[] bitBlocks){
        byte[] result = new byte[bitBlocks.length];

        for (int i = 0; i < bitBlocks.length; i++){
            result[i] = this.sBox.inverse().get(bitBlocks[i]);
        }
        return result;
    }

    private byte[] makeBitpermutation(byte[] bitBlocks){
        char[] result = new char[this.numberOfBitsPerBlock * this.numberOfBlocks];
        char[] bits = bitBlocksToBitString(bitBlocks).toCharArray();

        for (int i = 0; i < result.length; i++){
            int permutedBit = this.bitpermutation.get(i);
            result[permutedBit] = bits[i];
        }

        return bitStringToBitBlocks(result);
    }

    public String bitBlocksToBitString(byte[] bitBlocks) {
        StringBuilder result = new StringBuilder();
        for (byte block:bitBlocks) {
            result.append(this.binaryNumbers.get(block));
        }

        return result.toString();
    }

    public byte[] bitStringToBitBlocks(char[] bits){
        byte[] result = new byte[this.numberOfBlocks];

        int z = 0;
        for (int i = 0; i < 4; i++){
            StringBuilder bitsString = new StringBuilder();

            for (int j = z; j < z + 4; j++){
                bitsString.append(bits[j]);
            }

            byte block = this.binaryNumbers.inverse().get(bitsString.toString());
            result[i] = block;
            z += 4;
        }

        return result;
    }

    private byte[] finalShortRound(byte[] bitBlocks) {
        byte[] result;
        result = substitutionWithSbox(bitBlocks);

        return roundKeyAddition(result, this.rounds);
    }

}
