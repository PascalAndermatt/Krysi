package ch.fhnw.krysi;

import com.google.common.collect.BiMap;
import com.google.common.collect.HashBiMap;

import java.util.HashMap;
import java.util.Map;

public class SubstitutionPermutationNetwork {

    private final int rounds = 4;
    private final int numberOfBitsPerBlock = 4;
    private final int numberOfBlocks = 4;
    private byte[] key;
    private final int numberOfKeyBits = 32;

    private Map<Integer, byte[]> roundKeys = new HashMap<>();
    private Map<Integer, byte[]> roundKeysForDecryption = new HashMap<>();

    private BiMap<Byte, Byte> sBox = HashBiMap.create();
    private Map<Integer, Byte> bitpermutation = new HashMap<>();
    public BiMap<Byte, String> binaryNumbersOfBlocks = HashBiMap.create();

    public SubstitutionPermutationNetwork(byte[] key){
        if(key == null) throw new IllegalArgumentException("key is null");
        this.key = key;
        createSBox();
        createBitpermutation();
        createBinaryNumbers();
        createRoundKeys();
        createRoundKeysForDecryption();
    }

    private void createSBox(){
        byte[] sBox = new byte[]{14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7};

        for (int i = 0; i < sBox.length; i++){
            this.sBox.put((byte) i, sBox[i]);
        }
    }

    private void createBitpermutation() {
        byte[] bitPermutationsBox = new byte[]{0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15};

        for (int i = 0; i < bitPermutationsBox.length; i++){
            this.bitpermutation.put(i, bitPermutationsBox[i]);
        }
    }

    private void createBinaryNumbers(){
        this.binaryNumbersOfBlocks.put((byte)0, "0000");
        this.binaryNumbersOfBlocks.put((byte)1, "0001");
        this.binaryNumbersOfBlocks.put((byte)2, "0010");
        this.binaryNumbersOfBlocks.put((byte)3, "0011");
        this.binaryNumbersOfBlocks.put((byte)4, "0100");
        this.binaryNumbersOfBlocks.put((byte)5, "0101");
        this.binaryNumbersOfBlocks.put((byte)6, "0110");
        this.binaryNumbersOfBlocks.put((byte)7, "0111");
        this.binaryNumbersOfBlocks.put((byte)8, "1000");
        this.binaryNumbersOfBlocks.put((byte)9, "1001");
        this.binaryNumbersOfBlocks.put((byte)10, "1010");
        this.binaryNumbersOfBlocks.put((byte)11, "1011");
        this.binaryNumbersOfBlocks.put((byte)12, "1100");
        this.binaryNumbersOfBlocks.put((byte)13, "1101");
        this.binaryNumbersOfBlocks.put((byte)14, "1110");
        this.binaryNumbersOfBlocks.put((byte)15, "1111");
    }

    private void createRoundKeys(){
        for (int i = 0; i <= rounds; i++){

            byte[] roundKey = new byte[4];

            for (int j = 0; j < 4; j++){
                roundKey[j] = key[i + j];
            }

            roundKeys.put(i, roundKey);
        }
    }

    private void createRoundKeysForDecryption(){
        this.roundKeysForDecryption.put(0, this.roundKeys.get(this.rounds));

        for (int i = 1; i < this.rounds; i++){
            this.roundKeysForDecryption.put(i, this.permuteBits(this.getRoundKeys().get(this.rounds - i)));
        }

        this.roundKeysForDecryption.put(rounds, this.roundKeys.get(rounds - rounds));
    }

    byte[] encrypt(byte[] randomBitString){
        return this.executeSpnSteps(randomBitString, false);
    }

    private byte[] executeSpnSteps(byte[] encryptedString, boolean decryption){
        byte[] result;
        result = initialWhiteStep(encryptedString, decryption);

        for (int i = 1; i < this.rounds; i++){
            result = normalRoundStep(result, i, decryption);
        }

        result = finalShortRound(result, decryption);

        return result;
    }

    byte[] decrypt(byte[] encryptedString){
        return this.executeSpnSteps(encryptedString, true);
    }

    byte[] initialWhiteStep(byte[] randomBitString, boolean inverse) {
        return roundKeyAddition(randomBitString, 0, inverse);
    }

    private byte[] normalRoundStep(byte[] bitBlocks, int round, boolean inverse) {
        byte[] result;

        result = substitutionWithSbox(bitBlocks, inverse);
        result = permuteBits(result);
        result = roundKeyAddition(result, round, inverse);

        return result;
    }

    private byte[] roundKeyAddition(byte[] bitBlocks, int round, boolean inverse){
        byte[] result = new byte[4];

        for(int i = 0; i < bitBlocks.length; i++){
            result[i] = (inverse) ? (byte) (bitBlocks[i] ^ roundKeysForDecryption.get(round)[i])
                    : (byte) (bitBlocks[i] ^ roundKeys.get(round)[i]);
        }

        return result;
    }

    private byte[] substitutionWithSbox(byte[] bitBlocks, boolean inverse){
        byte[] result = new byte[bitBlocks.length];

        for (int i = 0; i < bitBlocks.length; i++){
            result[i] = (inverse) ? this.sBox.inverse().get(bitBlocks[i])
                                    :this.sBox.get(bitBlocks[i]);
        }
        return result;
    }

    private byte[] permuteBits(byte[] bitBlocks){
        char[] result = new char[this.numberOfBitsPerBlock * this.numberOfBlocks];
        char[] bits = bitBlocksToBitString(bitBlocks).toCharArray();

        for (int i = 0; i < result.length; i++){
            int permutedBit = this.bitpermutation.get(i);
            result[permutedBit] = bits[i];
        }

        return bitStringToBitBlocks(result);
    }

    String bitBlocksToBitString(byte[] bitBlocks) {
        StringBuilder result = new StringBuilder();
        for (byte block:bitBlocks) {
            result.append(this.binaryNumbersOfBlocks.get(block));
        }

        return result.toString();
    }

    byte[] bitStringToBitBlocks(char[] bits){
        byte[] result = new byte[this.numberOfBlocks];

        int z = 0;
        for (int i = 0; i < this.numberOfBlocks; i++){
            StringBuilder bitsString = new StringBuilder();

            for (int j = z; j < z + this.numberOfBitsPerBlock; j++){
                bitsString.append(bits[j]);
            }

            byte block = this.binaryNumbersOfBlocks.inverse().get(bitsString.toString());
            result[i] = block;
            z += 4;
        }

        return result;
    }

    private byte[] finalShortRound(byte[] bitBlocks, boolean inverse) {
        byte[] result;
        result = substitutionWithSbox(bitBlocks, inverse);

        return roundKeyAddition(result, this.rounds, inverse);
    }

    // Diese Methode ist nur für die Test-Cases
    Map<Integer, byte[]> getRoundKeys(){
        return this.roundKeys;
    }

    // Diese Methode ist nur für die Test-Cases
    Map<Integer, byte[]> getRoundKeysForDecryption(){
        return this.roundKeysForDecryption;
    }

}
