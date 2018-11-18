import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

public class MerckleTreeProofTask {

    public static void main(String[] args) {
        Scanner is = new Scanner(System.in);
        int h = is.nextInt();
        int n = is.nextInt();
        Map<Integer, String> mp = new HashMap<>();
        for (int i = 0; i < n; ++i) {
            int id = is.nextInt();
            String data = is.next();
            mp.put(id, data);
        }

        MerckleTreeProofBuilder mtpb = new MerckleTreeProofBuilder();
        mtpb.setHeight(h);
        mtpb.setLeafBlocks(mp);
        mtpb.prepare();

        int q = is.nextInt();
        while (q-- > 0) {
            int id = is.nextInt();
            System.out.println(id + " " + mtpb.getLeafBlockData(id));
            for (String proof : mtpb.buildProofForLeadBlock(id)) {
                System.out.println(proof);
            }
        }
    }
}

class MerckleTreeProofBuilder {

    private int height;
    private Map<Integer, byte[]> leafBlocks = new HashMap<>();
    private Map<Integer, byte[]> treeBlocks = new HashMap<>();

    final private Base64.Decoder decoder = Base64.getDecoder();
    final private Base64.Encoder encoder = Base64.getEncoder();

    private List<Byte> toByteList(byte[] lst) {
        List<Byte> res = new ArrayList<Byte>();
        for (int i = 0; i < lst.length; ++i) {
            res.add(lst[i]);
        }
        return res;
    }

    private byte[] toByteArray(List<Byte> ns) {
        byte[] res = new byte[ns.size()];
        for (int i = 0; i < ns.size(); ++i) {
            res[i] = ns.get(i).byteValue();
        }
        return res;
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

    private byte[] getTreeBlockHash(int id) {
        return treeBlocks.getOrDefault(id, null);
    }

    private String getBase64TreeBlockHash(int id) {
        byte[] temp = getTreeBlockHash(id);
        if (temp == null) {
            return "null";
        } else {
            return new String(encoder.encode(temp));
        }
    }

    private void setTreeBlockHash(int id, byte[] hash) {
        treeBlocks.put(id, hash.clone());
    }

    public void setHeight(int height) {
        this.height = height;
    }

    public void setLeafBlocks(Map<Integer, String> leafBlocks) {
        for(Map.Entry<Integer, String> current : leafBlocks.entrySet()) {
            this.leafBlocks.put(current.getKey(), decoder.decode(current.getValue()));
        }
    }

    public void prepare() {
        for(Map.Entry<Integer, byte[]> current : leafBlocks.entrySet()) {
            int id = current.getKey() + (1 << height) - 1;
            byte[] currentHash = sha256(current.getValue());
            setTreeBlockHash(id, currentHash);
            for (int i = 0; i < height; ++i) {
                if (id % 2 == 0) {
                    currentHash = sha256(getTreeBlockHash(id - 1), currentHash);
                } else {
                    currentHash = sha256(currentHash, getTreeBlockHash(id + 1));
                }
                id = (id - 1) / 2;
                setTreeBlockHash(id, currentHash);
            }
        }
    }

    public String getLeafBlockData(int id) {
        return leafBlocks.containsKey(id) ? new String(encoder.encode(leafBlocks.get(id)), StandardCharsets.UTF_8) : "null";
    }

    public List<String> buildProofForLeadBlock(int id) {
        List<String> res = new ArrayList<>();
        id += (1 << height) - 1;
        for(int i = 0; i < height; ++i) {
            if (id % 2 == 0) {
                res.add(getBase64TreeBlockHash(id - 1));
            } else {
                res.add(getBase64TreeBlockHash(id + 1));
            }
            id = (id - 1) / 2;
        }
        return res;
    }


}
