package ch.fhnw.krysi;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

public class SubstitutionPermutationNetworkTest {

    private SubstitutionPermutationNetwork spn;
    private RctrMode rctrMode;
    private char[] characters;
    private List<Character> characterList;
    private String decryptedString = "Gut gemacht!";
    private final byte[] randomBitString = {0b0000_0001, 0b0000_0010, 0b0000_1000, 0b0000_1111};
    private final byte[] key = {0b0000_0001, 0b0000_0001, 0b0000_0010, 0b0000_1000, 0b0000_1000, 0b0000_1100, 0b0000_0000, 0b0000_0000};

    @BeforeEach
    public void setup(){
        this.spn = new SubstitutionPermutationNetwork(this.key);
        this.rctrMode = new RctrMode();
        this.characters = decryptedString.toCharArray();
    }

    @AfterEach
    public  void tearDown(){
        this.spn = null;
    }

    @Test
    public void testRoundKeys()
    {
        Map<Integer, byte[]> roundKeys = new HashMap<>();

        roundKeys.put(0, new byte[]{0b0000_0001, 0b0000_0001, 0b0000_0010, 0b0000_1000});
        roundKeys.put(1, new byte[]{0b0000_0001, 0b0000_0010, 0b0000_1000, 0b0000_1000});
        roundKeys.put(2, new byte[]{0b0000_0010, 0b0000_1000, 0b0000_1000, 0b0000_1100});
        roundKeys.put(3, new byte[]{0b0000_1000, 0b0000_1000, 0b0000_1100, 0b0000_0000});
        roundKeys.put(4, new byte[]{0b0000_1000, 0b0000_1100, 0b0000_0000, 0b0000_0000});

        assertArrayEquals(roundKeys.get(0), spn.getRoundKeys().get(0));
        assertArrayEquals(roundKeys.get(1), spn.getRoundKeys().get(1));
        assertArrayEquals(roundKeys.get(2), spn.getRoundKeys().get(2));
        assertArrayEquals(roundKeys.get(3), spn.getRoundKeys().get(3));
        assertArrayEquals(roundKeys.get(4), spn.getRoundKeys().get(4));
    }

    @Test
    public void testRoundKeysForDecrypt()
    {
        Map<Integer, byte[]> roundKeysForDecrypt = new HashMap<>();

        roundKeysForDecrypt.put(0, new byte[]{0b0000_1000, 0b0000_1100, 0b0000_0000, 0b0000_0000});
        roundKeysForDecrypt.put(1, new byte[]{0b0000_1110, 0b0000_0010, 0b0000_0000, 0b0000_0000});
        roundKeysForDecrypt.put(2, new byte[]{0b0000_0111, 0b0000_0001, 0b0000_1000, 0b0000_0000});
        roundKeysForDecrypt.put(3, new byte[]{0b0000_0011, 0b0000_0000, 0b0000_0100, 0b0000_1000});
        roundKeysForDecrypt.put(4, new byte[]{0b0000_0001, 0b0000_0001, 0b0000_0010, 0b0000_1000});

        assertArrayEquals(roundKeysForDecrypt.get(0), spn.getRoundKeysForDecryption().get(0));
        assertArrayEquals(roundKeysForDecrypt.get(1), spn.getRoundKeysForDecryption().get(1));
        assertArrayEquals(roundKeysForDecrypt.get(2), spn.getRoundKeysForDecryption().get(2));
        assertArrayEquals(roundKeysForDecrypt.get(3), spn.getRoundKeysForDecryption().get(3));
        assertArrayEquals(roundKeysForDecrypt.get(4), spn.getRoundKeysForDecryption().get(4));
    }

    @Test
    public void testInitialWhiteStep()
    {
        byte[] expected = new byte[]{0b0000_0000, 0b0000_0011, 0b0000_1010, 0b0000_0111};
        byte[] actual = this.spn.initialWhiteStep(new byte[]{0b0000_0001, 0b0000_0010, 0b0000_1000, 0b0000_1111}, false);
        assertArrayEquals(expected, actual);
    }



    @Test
    public void checkAllSpn()
    {

        byte[] expected = {0b0000_1010, 0b0000_1110, 0b0000_1011, 0b0000_0100};
        byte[] result = this.spn.encrypt(this.randomBitString);
        assertArrayEquals(expected, result);
    }

    @Test
    public void checkAllSpnDecrypt()
    {

        byte[] expected = {0b0000_0001, 0b0000_0010, 0b0000_1000, 0b0000_1111};
        byte[] result = this.spn.decrypt(new byte[]{0b0000_1010, 0b0000_1110, 0b0000_1011, 0b0000_0100});
        assertArrayEquals(expected, result);
    }

    @Test
    public void checkCtrModus()
    {
        StringBuilder builder = new StringBuilder();
        List<Character> characters = rctrMode.getDecryptedCharacters();

        for (char character: characters) {
            builder.append(character);
        }
        String actual = builder.toString();
        assertEquals(this.decryptedString, actual);
    }

}
