package ch.fhnw.krysi;


import org.apache.commons.lang3.StringUtils;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class RctrMode {

    private final byte[] key = {0b0000_0011, 0b0000_1010, 0b0000_1001, 0b0000_0100, 0b0000_1101, 0b0000_0110, 0b0000_0011, 0b0000_1111};
    private SubstitutionPermutationNetwork spn;

    private String y = "0000010011010010" + "0000101110111000" + "0000001010001111" +
                        "1000111001111111" + "0110000001010001" + "0100001110100000" +
                        "0001001101100111" + "0010101110110000";
    private int blockLength = 16;

    private Map<Integer, byte[]> yBlocks = new HashMap<>();
    private Integer initialVector;

    private Map<Integer, Integer> vectorsForSpn = new HashMap<>();
    private Map<Integer, byte[]> encryptedVectorsFromSpn = new HashMap<>();
    private Map<Integer, byte[]> x = new HashMap<>();

    private List<Character> decryptedCharacters = new ArrayList<>();


    public RctrMode(){
        this.spn = new SubstitutionPermutationNetwork(this.key);
        readInitialVector();
        createVectorsForSpn();
        divideYintoBlocks();
        encryptVectorsWithSpn();
        decryptYtoX();
        decryptXtoAsciiCharacters();
    }

    private void divideYintoBlocks(){
        this.y = this.y.substring(16);

        for (int i = 0; i < (y.length() / 16); i++){
            this.yBlocks.put(i, bitStringToBlocks(Integer.parseUnsignedInt(this.getBlockOfY(i), 2)));
        }
    }

    private String getBlockOfY(int block){
        return this.y.substring(this.blockLength * block, (this.blockLength * block) + this.blockLength);
    }

    private void readInitialVector(){
        String initialVector = this.y.substring(0, 16);
        this.initialVector = Integer.parseUnsignedInt(initialVector, 2);
    }

    private void createVectorsForSpn(){
        for (int i = 0; i < ((y.length() / this.blockLength) - 1); i++){
            this.vectorsForSpn.put(i, (vectorCalculation(this.initialVector, i)));
        }
    }

    private Integer vectorCalculation(Integer initialVector, int plus){
        return ((initialVector + plus) % ((int) Math.pow(2, this.blockLength)));
    }

    private byte[] bitStringToBlocks(Integer bitString){
        String bits = Integer.toBinaryString(bitString);

        if (bits.length() < 16){
            bits = StringUtils.leftPad(bits, 16, '0');
        }

        char[] bitsArray = bits.toCharArray();

        return this.spn.bitStringToBitBlocks(bitsArray);
    }

    private void encryptVectorsWithSpn(){
        for (int i = 0; i < vectorsForSpn.size(); i++){
            this.encryptedVectorsFromSpn.put(i, this.spn.encrypt(bitStringToBlocks(this.vectorsForSpn.get(i))));
        }
    }

    private void decryptYtoX(){
        for (int i = 0; i < this.encryptedVectorsFromSpn.size(); i++){
            byte[] decryptedBlock = xOrBitsFromYwithEncryptedVector(encryptedVectorsFromSpn.get(i), i);
            this.x.put(i, decryptedBlock);
        }
    }

    private void decryptXtoAsciiCharacters(){
        String bitString = removePaddingFromX();

        for (int i = 0; i < bitString.length() / 8; i++){

            Integer encryptedX = Integer.parseUnsignedInt(bitString.substring(8 * i, 8 * i + 8 ), 2);
            this.decryptedCharacters.add((char)encryptedX.intValue());
        }
    }

    private String removePaddingFromX() {
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < this.x.size(); i++){
            builder.append(spn.bitBlocksToBitString(this.x.get(i)));
        }

        String bitString = builder.toString();
        String result = bitString.substring(0, bitString.lastIndexOf("1"));

        return result;
    }

    private byte[] xOrBitsFromYwithEncryptedVector(byte[] encryptedVectorFromSpn, int yBlock){
        byte[] result = new byte[encryptedVectorFromSpn.length];

        for (int i = 0; i < encryptedVectorFromSpn.length; i++){

            result[i] = (byte) (encryptedVectorFromSpn[i] ^ this.yBlocks.get(yBlock)[i]);
        }

        return result;
    }

    List<Character> getDecryptedCharacters(){
       return this.decryptedCharacters;
    }
}
