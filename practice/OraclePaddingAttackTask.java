import java.util.Base64;
import java.util.Scanner;

public class OraclePaddingAttackTask {

    final Base64.Decoder decoder = Base64.getDecoder();
    final Base64.Encoder encoder = Base64.getEncoder();

    final int blockSize = 16;

    private boolean ask(Scanner is, String emsg, byte[] iv) {
        System.out.println("NO");
        System.out.println(emsg);
        System.out.println(encoder.encodeToString(iv));
        String verdict = is.next();
        return verdict.equals("Ok");
    }

    private void answer(String ans) {
        System.out.println("YES");
        System.out.println(ans);
    }

    void run(Scanner is) {
        String encodedMsg = is.next();
        byte[] iv = decoder.decode(is.next());
        iv[2] ^= (byte) 14 ^ (byte) 'A';
        if (ask(is, encodedMsg, iv)) {
            for (int i = 3; i < blockSize; ++i) {
                iv[i] ^= (byte) 14 ^ (byte) 13;
            }
            if (ask(is, encodedMsg, iv)) {
                answer("N/A");
            } else {
                answer("Yes");
            }
        } else {
            answer("No");
        }
    }

    public static void main(String... args) {
        Scanner is = new Scanner(System.in);
        new Main().run(is);
    }
}
