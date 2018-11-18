import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;


public class MerckleTreeCheckTask {

    public static void main(String... args) {
        Scanner is = new Scanner(System.in);
        int h = is.nextInt(); is.nextLine();
        String topHash = is.nextLine().trim();

        MerckleTreeChecker checker = new MerckleTreeChecker(topHash);

        int q = is.nextInt();
        while (--q >= 0) {
            byte[][] lst = new byte[h][];

            int id = is.nextInt();
            byte[] data = is.nextLine().trim().getBytes();
            if (Arrays.equals(data, "null".getBytes())) {
                data = null;
            }
            checker.setId(id);
            checker.setData(data);

            for (int i = 0; i < h; ++i) {
                lst[i] = is.nextLine().trim().getBytes();
                if (Arrays.equals(lst[i], "null".getBytes())) {
                    lst[i] = null;
                }
            }

            checker.setNeighboures(Arrays.asList(lst));

            if (checker.check()) {
                System.out.println("YES");
            } else {
                System.out.println("NO");
            }
        }
    }
}

class MerckleTreeChecker {

    private byte[] topHash;
    private List<byte[]> neighboures;
    private byte[] data;
    private int id;

    final private Base64.Decoder decoder = Base64.getDecoder();

    private List<Byte> toByteList(byte[] lst) {
        List<Byte> res = new ArrayList<Byte>();
        for (int i = 0; i < lst.length; ++i) {
            res.add(lst[i]);
        }
        return res;
    }

    public MerckleTreeChecker(String topHash) {
        this.topHash = decoder.decode(topHash);
    }

    public void setNeighboures(List<byte[]> neighboures) {
        this.neighboures = neighboures;
    }

    public void setData(byte[] data) {
        if (data == null) {
            this.data = null;
        } else {
            this.data = decoder.decode(data);
        }
    }

    public void setId(int id) {
        this.id = id;
    }

    public boolean check() {
        byte[] currentHash = sha256(data);
        for (int i = 0; i < neighboures.size(); ++i) {
            byte[] sn = neighboures.get(i) == null ?  null : decoder.decode(neighboures.get(i));
            if (id % 2 == 0) {
                currentHash = sha256(currentHash, sn);
            } else {
                currentHash = sha256(sn, currentHash);
            }
            id /= 2;
        }
        return Arrays.equals(currentHash, topHash);
    }

    private byte[] sha256(byte[] s) {
        if (s == null) {
            return null;
        }
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
        List<Byte> ns = new ArrayList<>();
        ns.add(Byte.parseByte("0"));
        ns.addAll(toByteList(s));
        return digest.digest(toByteArray(ns));
    }

    private byte[] toByteArray(List<Byte> ns) {
        byte[] res = new byte[ns.size()];
        for (int i = 0; i < ns.size(); ++i) {
            res[i] = ns.get(i).byteValue();
        }
        return res;
    }

    private byte[] sha256(byte[] a, byte[] b) {
        if (a == null && b == null) {
            return null;
        }
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
        List<Byte> ns = new ArrayList<>();
        ns.add(Byte.parseByte("1"));
        if (a != null) {
            ns.addAll(toByteList(a));
        }
        ns.add(Byte.parseByte("2"));
        if (b != null) {
            ns.addAll(toByteList(b));
        }
        return digest.digest(toByteArray(ns));
    }
}


/*
3
mjlPuB+DhKr1xL1MLyG/OM7iog2GgjqyyVsmpXyDOG8=
4
0 null
wrWzhwQpSS/S3/9DoKYhX9X2ESfcEAd24GvbAtTVaw4=
rBdCkLCyPdT17nxs9ubPhQyNlgrokFTD9xdYUNPnjSE=
null
1 acab
null
rBdCkLCyPdT17nxs9ubPhQyNlgrokFTD9xdYUNPnjSE=
null
2 cacx
null
c6WRavDoPHscMlVKF9xYcFZBz1b83qinYC1AqQcE+i0=
null
3 null
hpnxjn69vVsDnfP/0O851ndk5gU1yD9exgwh/+oyjL8=
c6WRavDoPHscMlVKF9xYcFZBz1b83qinYC1AqQcE+i0=
null

*/
