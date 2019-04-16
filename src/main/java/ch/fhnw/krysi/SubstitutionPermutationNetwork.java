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
    private Map<Integer, Integer> bitpermutation = new HashMap<>();
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
        this.roundKeysForDecryption.put(0, this.roundKeys.get(this.rounds));

        for (int i = 1; i < this.rounds; i++){
            this.roundKeysForDecryption.put(i, this.permuteBits(this.getRoundKeys().get(this.rounds - i)));
        }

        this.roundKeysForDecryption.put(rounds, this.roundKeys.get(rounds - rounds));
    }

    public byte[] encrypt(byte[] randomBitString){
        return this.executeSpnSteps(randomBitString, false);
    }

    public byte[] executeSpnSteps(byte[] encryptedString, boolean decryption){
        byte[] result;
        result = initialWhiteStep(encryptedString, decryption);

        for (int i = 1; i < this.rounds; i++){
            result = normalRoundStep(result, i, decryption);
        }

        result = finalShortRound(result, decryption);

        return result;
    }

    public byte[] decrypt(byte[] encryptedString){
        return this.executeSpnSteps(encryptedString, true);
    }

    public byte[] initialWhiteStep(byte[] randomBitString, boolean inverse) {
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

    public String bitBlocksToBitString(byte[] bitBlocks) {
        StringBuilder result = new StringBuilder();
        for (byte block:bitBlocks) {
            result.append(this.binaryNumbersOfBlocks.get(block));
        }

        return result.toString();
    }

    public byte[] bitStringToBitBlocks(char[] bits){
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
    public Map<Integer, byte[]> getRoundKeys(){
        return this.roundKeys;
    }

    // Diese Methode ist nur für die Test-Cases
    public Map<Integer, byte[]> getRoundKeysForDecryption(){
        return this.roundKeysForDecryption;
    }

}
