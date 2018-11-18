import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

public class MerkleTreeSignatureAttackTask {

    private static String[] genHash = new String[256];

    private static byte[][][] sk0 = new byte[256][256][32];
    private static byte[][][] sk1 = new byte[256][256][32];

    private static byte[] sha256(byte[] s) {
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
        return digest.digest(s);
    }

    private static String reverseString(String s) {
        char[] res = new char[s.length()];
        for (int i = 0; i < s.length(); ++i) {
            res[i] = (s.charAt(i) == '0' ? '1' : '0');
        }
        return new String(res);
    }

    private static String generateHash(int id) {
        if (genHash[id] != null) {
            genHash[id] = reverseString(genHash[id]);
        } else {
            StringBuilder res = new StringBuilder();
            for (int i = 0; i < 256; ++i) {
                Random rnd = new Random();
                res.append(rnd.nextInt(2) + '0');
            }
            genHash[id] = res.toString();
        }
        return genHash[id];
    }

    private static boolean checkSignature(String signature64, String pk64, String hsh) {
        byte[] signature = Base64.getDecoder().decode(signature64);
        byte[] pk12 = Base64.getDecoder().decode(pk64);
        byte[] pk1 = new byte[pk12.length / 2];
        byte[] pk2 = new byte[pk12.length / 2];
        System.arraycopy(pk12, 0, pk1,0, pk1.length);
        System.arraycopy(pk12, pk1.length, pk2,0, pk2.length);
        for (int i = 0; i < 256; ++i) {
             byte[] curBlockFromSign = sha256(Arrays.copyOfRange(signature, i * 256 / 8, (i + 1) * 256 / 8));
             byte[] curBlockFromPK = Arrays.copyOfRange(hsh.charAt(i) == '0' ? pk1 : pk2, i * 256 / 8, (i + 1) * 256 / 8);
             if (!Arrays.equals(curBlockFromSign, curBlockFromPK)) {
                 return false;
             }
        }

        return true;
    }

    private static void updateSecretKeys(String signature64, String pk64, String hsh, int keyId) {
        byte[] signature = Base64.getDecoder().decode(signature64);
        byte[] pk12 = Base64.getDecoder().decode(pk64);
        byte[] pk1 = new byte[pk12.length / 2];
        byte[] pk2 = new byte[pk12.length / 2];

        System.arraycopy(pk12, 0, pk1,0, pk1.length);
        System.arraycopy(pk12, pk1.length, pk2,0, pk2.length);

        for (int i = 0; i < 256; ++i) {
            byte[] curBlockFromSign = Arrays.copyOfRange(signature, i * 256 / 8, (i + 1) * 256 / 8);
            if (hsh.charAt(i) == '0') {
                sk0[keyId][i] = curBlockFromSign;
            } else {
                sk1[keyId][i] = curBlockFromSign;
            }
        }
    }

    private static String signMessage(String hashedMsg, int keyId) {
        byte[] res = new byte[256 * 32];
        for (int i = 0; i < 256; ++i) {
            if (hashedMsg.charAt(i) == '0') {
                if (sk0[keyId][i] == null) {
                    return null;
                }
                System.arraycopy(sk0[keyId][i], 0, res, i * 256 / 8, 256 / 8);
            } else {
                if (sk1[keyId][i] == null) {
                    return null;
                }
                System.arraycopy(sk1[keyId][i], 0, res, i * 256 / 8, 256 / 8);
            }
        }
        return Base64.getEncoder().encodeToString(res);
    }

    public static void main(String[] args) {

        for (int i = 0; i < 256; ++i) {
            for (int j = 0; j < 256; ++j)
                sk0[i][j] = sk1[i][j] = null;
        }

        Scanner is = new Scanner(System.in);
        String pub = is.nextLine().trim();
        MerkleTree mt = new MerkleTree(8 + 1, pub);
        for (int i = 0; i < 1000; ++i) {
            String temp = is.nextLine();
            int key_id = Integer.parseInt(temp.trim());
            String hashMsg = generateHash(key_id);
            System.out.println(hashMsg);
            String signature = is.nextLine().trim();
            String subpub = is.nextLine().trim();
            mt.setLeafNode(key_id, subpub);
            List<String> proof = new ArrayList<>();
            for (int k = 0; k < 8; ++k) {
                proof.add(is.nextLine().trim());
            }

            String msg = is.nextLine().trim();

            if (!mt.check(proof, key_id)) {
                System.out.println("NO");
                System.out.println("NO");
                continue;
            }

            if (!checkSignature(signature, subpub, hashMsg)) {
                System.out.println("NO");
                System.out.println("NO");
                continue;
            }

            updateSecretKeys(signature, subpub, hashMsg, key_id);
            System.out.println("YES");

            String newSignature = signMessage(msg, key_id);
            if (newSignature != null) {
                System.out.println("YES");
                System.out.println(newSignature);
                break;
            } else {
                System.out.println("NO");
            }
        }
    }
}

class MerkleTree {

    class Node {
        private byte[] hash;
        private Node left;
        private Node right;

        public Node(Node left, Node right) {
            this.left = left;
            this.right = right;
            this.hash = null;
        }

        public Node() {
            left = right = null;
            this.hash = null;
        };
    }

    private Node root;
    private int height;

    final private Base64.Decoder decoder = Base64.getDecoder();
    final private Base64.Encoder encoder = Base64.getEncoder();

    private Node build_tree(int level) {
        if (level == 0) {
            return new Node();
        } else {
            return new Node(build_tree(level - 1), build_tree(level - 1));
        }
    }

    public MerkleTree(int levels, String pub) {
        height = levels - 1;
        root = build_tree(levels);
        root.hash = decoder.decode(pub);
    }

    private Node locateLeaf(Node cur, int id, int l, int r) {
        if (l == r) {
            return cur;
        }
        int mid = (l + r) / 2;
        if (id <= mid) {
            return locateLeaf(cur.left, id, l, mid);
        } else {
            return locateLeaf(cur.right, id, mid + 1, r);
        }
    }

    private Node locateLeaf(int id) {
        return locateLeaf(root, id, 0, (1 << height) - 1);
    }

    public void setLeafNode(int leafId, String hash) {
        Node leaf = locateLeaf(leafId);
        leaf.hash = decoder.decode(hash);
    }

    public boolean check(List<String> proof, int id) {
        byte[] currentHash = sha256(locateLeaf(id).hash);
        for (int i = 0; i < proof.size(); ++i) {
            byte[] sn = proof.get(i) == null ?  null : decoder.decode(proof.get(i));
            if (id % 2 == 0) {
                currentHash = sha256(currentHash, sn);
            } else {
                currentHash = sha256(sn, currentHash);
            }
            id /= 2;
        }
        return Arrays.equals(currentHash, root.hash);
    }

    private void addProof(Node cur, List<String> proof, int id, int l, int r, int pos) {
        int mid = (l + r) / 2;
        if (id <= mid) {
            addProof(cur.left, proof, id, l, mid, pos - 1);
            cur.right.hash = decoder.decode(proof.get(pos));
        } else {
            addProof(cur.right, proof, id, mid + 1, r, pos - 1);
            cur.left.hash = decoder.decode(proof.get(pos));
        }
    }

    public void addProof(List<String> proof, int id) {
        addProof(root, proof, id, 0, (1 << height) - 1, 7);
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
            res[i] = ns.get(i);
        }
        return res;
    }

    private List<Byte> toByteList(byte[] lst) {
        List<Byte> res = new ArrayList<>();
        for (int i = 0; i < lst.length; ++i) {
            res.add(lst[i]);
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
