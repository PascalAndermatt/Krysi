package ch.fhnw.krysi;

import java.util.List;

public class App
{
    public static void main( String[] args) {
        RctrMode rctrMode = new RctrMode();
        printList(rctrMode.getDecryptedCharacters());
    }

    private static void printList(List<Character> characters) {
        for (char character:characters) {
            System.out.println(character + " ");
        }
    }
}
