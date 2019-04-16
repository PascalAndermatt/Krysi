package ch.fhnw.krysi;


import org.apache.commons.lang3.StringUtils;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class RctrMode {

    private SubstitutionPermutationNetwork spn;

    private String y = "0000010011010010" + "0000101110111000" + "0000001010001111" +
                        "1000111001111111" + "0110000001010001" + "0100001110100000" +
                        "0001001101100111" + "0010101110110000";
    private int blockLength = 16;

    private Map<Integer, byte[]> yAsBytes = new HashMap<>();

    private Map<Integer, Integer> randomBitStrings = new HashMap<>();
    private Map<Integer, byte[]> e = new HashMap<>();
    private Map<Integer, byte[]> x = new HashMap<>();


    public RctrMode(){
        this.spn = new SubstitutionPermutationNetwork();
        createRandomBitStrings();
        createYintoBlocks();
        decryptY();
        decryptX();
    }

    // y-1 muss nicht mehr dabei sein, hier wird y0 - yn-1 zerlegt
    public void createYintoBlocks(){
        int test2 = this.y.length();
        this.y = this.y.substring(16);
        int test = this.y.length();
        for (int i = 0; i < (y.length() / 16); i++){
            this.yAsBytes.put(i, bitStringToBlocks(Integer.parseUnsignedInt(this.y.substring(16 * i, (16 * i) + 16), 2)));
        }
    }

    public Integer getRandomBitString(){
        String randomBitString = this.y.substring(0, 16);
        Integer result = Integer.parseUnsignedInt(randomBitString, 2);

        return result;
    }

    public void createRandomBitStrings(){
        for (int i = 0; i < ((y.length() / this.blockLength) - 1); i++){
            this.randomBitStrings.put(i, (bitStringPlus(this.getRandomBitString(), i)));
        }
    }

    private Integer bitStringPlus(Integer bitString, int plus){
        return ((bitString + plus) % ((int) Math.pow(2, this.blockLength)));
    }

    public byte[] bitStringToBlocks(Integer bitString){
        String bits = Integer.toBinaryString(bitString);

        if (bits.length() < 16){
            bits = StringUtils.leftPad(bits, 16, '0');
        }

        if(bits.length() > 16){
            bits = bits.substring(0, 16);
        }

        char[] bitsArray = bits.toCharArray();

        return this.spn.bitStringToBitBlocks(bitsArray);
    }

    public void decryptY(){
        for (int i = 0; i < randomBitStrings.size(); i++){
            this.e.put(i, this.spn.encrypt(bitStringToBlocks(this.randomBitStrings.get(i))));
        }

        for (int i = 0; i < this.e.size(); i++){
            byte[] block = xOr(e.get(i), i);
            this.x.put(i, block);
        }
    }

    public void decryptX(){
        List<Character> characters = new ArrayList<>();
        String bitString = removePadding();

        for (int i = 0; i < bitString.length() / 8; i++){

            Integer encryptedX = Integer.parseUnsignedInt(bitString.substring(8 * i, 8 * i + 8 ), 2);
            characters.add((char)encryptedX.intValue());
        }

//        for (int i = 0; i < this.x.size(); i++){
//
//            String bitStringOfX = this.spn.bitBlocksToBitString(this.x.get(i));
//            System.out.println(bitStringOfX);
//            //String bitString1 = bitStringOfX.substring(0, 8)
//            Integer encryptedX = Integer.parseUnsignedInt(bitStringOfX.substring(0, bitStringOfX.lastIndexOf("1") ), 2);
//            characters.add((char)encryptedX.intValue());
//        }

        printList(characters);
    }

    private String removePadding() {
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < this.x.size(); i++){
            builder.append(spn.bitBlocksToBitString(this.x.get(i)));
        }

        String test = builder.toString();
        String result = test.substring(0, test.lastIndexOf("1"));

        return result;
    }

    private void printList(List<Character> characters) {
        for (char character:characters) {
            System.out.println(character + " ");
        }
    }

    public byte[] xOr(byte[] bitBlocks, int yBlock){
        byte[] result = new byte[bitBlocks.length];

        for (int i = 0; i < bitBlocks.length; i++){

            result[i] = (byte) (bitBlocks[i] ^ this.yAsBytes.get(yBlock)[i]);
        }

        return result;
    }

//    private byte[] xOrOfBlocks(byte[] bitBlocks, int round){
//        byte[] result = new byte[4];
//
//        for(int i = 0; i < bitBlocks.length; i++){
//            result[i] = (byte) (bitBlocks[i] ^ roundKeys.get(round)[i]);
//        }
//
//        return result;
//    }


}
