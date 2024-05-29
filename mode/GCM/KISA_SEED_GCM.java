import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;

public class KISA_SEED_GCM
{
    private static int BLOCK_SIZE_SEED = 16;

    private static void SHIFTR1(int[] R)
    {
        R[3] = ((R[3] >> 1) & 0x7FFFFFFF) ^ ((R[2] << 31) & 0x80000000);
        R[2] = ((R[2] >> 1) & 0x7FFFFFFF) ^ ((R[1] << 31) & 0x80000000);
        R[1] = ((R[1] >> 1) & 0x7FFFFFFF) ^ ((R[0] << 31) & 0x80000000);
        R[0] = ((R[0] >> 1) & 0x7FFFFFFF);
    }
    
    private static void SHIFTR8(int[] R)
    {
        R[3] = ((R[3] >> 8) & 0x00FFFFFF) ^ ((R[2] << 24) & 0xFF000000);
        R[2] = ((R[2] >> 8) & 0x00FFFFFF) ^ ((R[1] << 24) & 0xFF000000);
        R[1] = ((R[1] >> 8) & 0x00FFFFFF) ^ ((R[0] << 24) & 0xFF000000);
        R[0] = ((R[0] >> 8) & 0x00FFFFFF);
    }

    private static void XOR128(int[] R, int[] A, int[] B)
    {
        R[0] = A[0] ^ B[0];
        R[1] = A[1] ^ B[1];
        R[2] = A[2] ^ B[2];
        R[3] = A[3] ^ B[3];
    }

    private static void INCREASE(int[] ctr)
    {
        if (ctr[3] == 0xFFFFFFFF)
        {
            ctr[2]++;
            ctr[3] = 0;
        }
        else
        {
            ctr[3]++;
        }
    }

    private static void ZERO128(int[] a) { a[0] = 0x00000000; a[1] = 0x00000000; a[2] = 0x00000000; a[3] = 0x00000000; }

    private static void Byte2Word(int[] dst, byte[] src, int src_offset, int srcLen)
    {
        int i = 0;
        int remain = 0;

        for (i = 0; i < srcLen; i++)
        {
            remain = i & 3;

            if (remain == 0)
                dst[i >> 2]  = ((src[src_offset + i] & 0x0FF) << 24);
            else if (remain == 1)
                dst[i >> 2] ^= ((src[src_offset + i] & 0x0FF) << 16);
            else if (remain == 2)
                dst[i >> 2] ^= ((src[src_offset + i] & 0x0FF) <<  8);
            else
                dst[i >> 2] ^= ( src[src_offset + i] & 0x0FF);
        }
    }

    private static void Word2Byte(byte[] dst, int dst_offset, int[] src, int srcLen)
    {
        int i = 0;
        int remain = 0;

        for (i = 0; i < srcLen; i++)
        {
            remain = i & 3;

            if (remain == 0)
                dst[dst_offset + i] = (byte)(src[i >> 2] >> 24);
            else if (remain == 1)
                dst[dst_offset + i] = (byte)(src[i >> 2] >> 16);
            else if (remain == 2)
                dst[dst_offset + i] = (byte)(src[i >> 2] >> 8);
            else
                dst[dst_offset + i] = (byte) src[i >> 2];
        }
    }
    
    private static final int R8[] =
    {
        0x00000000, 0x01c20000, 0x03840000, 0x02460000, 0x07080000, 0x06ca0000, 0x048c0000, 0x054e0000,
        0x0e100000, 0x0fd20000, 0x0d940000, 0x0c560000, 0x09180000, 0x08da0000, 0x0a9c0000, 0x0b5e0000,
        0x1c200000, 0x1de20000, 0x1fa40000, 0x1e660000, 0x1b280000, 0x1aea0000, 0x18ac0000, 0x196e0000,
        0x12300000, 0x13f20000, 0x11b40000, 0x10760000, 0x15380000, 0x14fa0000, 0x16bc0000, 0x177e0000,
        0x38400000, 0x39820000, 0x3bc40000, 0x3a060000, 0x3f480000, 0x3e8a0000, 0x3ccc0000, 0x3d0e0000,
        0x36500000, 0x37920000, 0x35d40000, 0x34160000, 0x31580000, 0x309a0000, 0x32dc0000, 0x331e0000,
        0x24600000, 0x25a20000, 0x27e40000, 0x26260000, 0x23680000, 0x22aa0000, 0x20ec0000, 0x212e0000,
        0x2a700000, 0x2bb20000, 0x29f40000, 0x28360000, 0x2d780000, 0x2cba0000, 0x2efc0000, 0x2f3e0000,
        0x70800000, 0x71420000, 0x73040000, 0x72c60000, 0x77880000, 0x764a0000, 0x740c0000, 0x75ce0000,
        0x7e900000, 0x7f520000, 0x7d140000, 0x7cd60000, 0x79980000, 0x785a0000, 0x7a1c0000, 0x7bde0000,
        0x6ca00000, 0x6d620000, 0x6f240000, 0x6ee60000, 0x6ba80000, 0x6a6a0000, 0x682c0000, 0x69ee0000,
        0x62b00000, 0x63720000, 0x61340000, 0x60f60000, 0x65b80000, 0x647a0000, 0x663c0000, 0x67fe0000,
        0x48c00000, 0x49020000, 0x4b440000, 0x4a860000, 0x4fc80000, 0x4e0a0000, 0x4c4c0000, 0x4d8e0000,
        0x46d00000, 0x47120000, 0x45540000, 0x44960000, 0x41d80000, 0x401a0000, 0x425c0000, 0x439e0000,
        0x54e00000, 0x55220000, 0x57640000, 0x56a60000, 0x53e80000, 0x522a0000, 0x506c0000, 0x51ae0000,
        0x5af00000, 0x5b320000, 0x59740000, 0x58b60000, 0x5df80000, 0x5c3a0000, 0x5e7c0000, 0x5fbe0000,
        0xe1000000, 0xe0c20000, 0xe2840000, 0xe3460000, 0xe6080000, 0xe7ca0000, 0xe58c0000, 0xe44e0000,
        0xef100000, 0xeed20000, 0xec940000, 0xed560000, 0xe8180000, 0xe9da0000, 0xeb9c0000, 0xea5e0000,
        0xfd200000, 0xfce20000, 0xfea40000, 0xff660000, 0xfa280000, 0xfbea0000, 0xf9ac0000, 0xf86e0000,
        0xf3300000, 0xf2f20000, 0xf0b40000, 0xf1760000, 0xf4380000, 0xf5fa0000, 0xf7bc0000, 0xf67e0000,
        0xd9400000, 0xd8820000, 0xdac40000, 0xdb060000, 0xde480000, 0xdf8a0000, 0xddcc0000, 0xdc0e0000,
        0xd7500000, 0xd6920000, 0xd4d40000, 0xd5160000, 0xd0580000, 0xd19a0000, 0xd3dc0000, 0xd21e0000,
        0xc5600000, 0xc4a20000, 0xc6e40000, 0xc7260000, 0xc2680000, 0xc3aa0000, 0xc1ec0000, 0xc02e0000,
        0xcb700000, 0xcab20000, 0xc8f40000, 0xc9360000, 0xcc780000, 0xcdba0000, 0xcffc0000, 0xce3e0000,
        0x91800000, 0x90420000, 0x92040000, 0x93c60000, 0x96880000, 0x974a0000, 0x950c0000, 0x94ce0000,
        0x9f900000, 0x9e520000, 0x9c140000, 0x9dd60000, 0x98980000, 0x995a0000, 0x9b1c0000, 0x9ade0000,
        0x8da00000, 0x8c620000, 0x8e240000, 0x8fe60000, 0x8aa80000, 0x8b6a0000, 0x892c0000, 0x88ee0000,
        0x83b00000, 0x82720000, 0x80340000, 0x81f60000, 0x84b80000, 0x857a0000, 0x873c0000, 0x86fe0000,
        0xa9c00000, 0xa8020000, 0xaa440000, 0xab860000, 0xaec80000, 0xaf0a0000, 0xad4c0000, 0xac8e0000,
        0xa7d00000, 0xa6120000, 0xa4540000, 0xa5960000, 0xa0d80000, 0xa11a0000, 0xa35c0000, 0xa29e0000,
        0xb5e00000, 0xb4220000, 0xb6640000, 0xb7a60000, 0xb2e80000, 0xb32a0000, 0xb16c0000, 0xb0ae0000,
        0xbbf00000, 0xba320000, 0xb8740000, 0xb9b60000, 0xbcf80000, 0xbd3a0000, 0xbf7c0000, 0xbebe0000
    };
    
    private static void makeM8(int[][] M, int[] H)
    {
        int i = 64, j = 0;
        int[] temp = new int[4];
    
        M[128][0] = H[0];
        M[128][1] = H[1];
        M[128][2] = H[2];
        M[128][3] = H[3];
    
        while (i > 0)
        {
            temp[0] = M[i << 1][0];
            temp[1] = M[i << 1][1];
            temp[2] = M[i << 1][2];
            temp[3] = M[i << 1][3];
    
            if ((temp[3] & 0x01) == 1)
            {
                SHIFTR1(temp);
                temp[0] ^= 0xE1000000;
            }
            else
            {
                SHIFTR1(temp);
            }
    
            M[i][0] = temp[0];
            M[i][1] = temp[1];
            M[i][2] = temp[2];
            M[i][3] = temp[3];
    
            i >>= 1;
        }
    
        i = 2;
    
        while (i < 256)
        {
            for (j = 1; j < i; j++)
            {
                M[i + j][0] = M[i][0] ^ M[j][0];
                M[i + j][1] = M[i][1] ^ M[j][1];
                M[i + j][2] = M[i][2] ^ M[j][2];
                M[i + j][3] = M[i][3] ^ M[j][3];
            }
    
            i <<= 1;
        }
    
        M[0][0] = 0;
        M[0][1] = 0;
        M[0][2] = 0;
        M[0][3] = 0;
    }
    
    private static void GHASH_8BIT(int[] out, int[] in, int[][] M, int[] R)
    {
        int[] W = new int[4];
        int[] Z= new int[4];
        int temp = 0, i = 0;
    
        XOR128(Z, out, in);
    
        for (i = 0; i < 15; i++)
        {
            temp = ((Z[3 - (i >> 2)] >> ((i & 3) << 3)) & 0x0FF);
    
            W[0] ^= M[temp][0];
            W[1] ^= M[temp][1];
            W[2] ^= M[temp][2];
            W[3] ^= M[temp][3];
    
            temp = W[3] & 0x0FF;
            
            SHIFTR8(W);
            W[0] ^= R[temp];
        }
    
        temp = (Z[0] >> 24) & 0xFF;
    
        out[0] = W[0] ^ M[temp][0];
        out[1] = W[1] ^ M[temp][1];
        out[2] = W[2] ^ M[temp][2];
        out[3] = W[3] ^ M[temp][3];
    }
        
    public int SEED_GCM_Encryption(
        byte[] ct,
        byte[] pt, int ptLen,
        int macLen,
        byte[] nonce, int nonceLen,
        byte[] aad, int aadLen,
        byte[] mKey)
    {
        int[] rKey = new int[100];
        int[] H = new int[4];
        int[] Z = new int[4];
        int[] tmp = new int[8];
        int[] GCTR_in = new int[4];
        int[] GCTR_out = new int[4];
        int[] GHASH_in = new int[4];
        int[] GHASH_out = new int[4];
        int[][] M8 = new int[256][4];
        int i = 0;
        KISA_SEED seed = new KISA_SEED();
    
        if (macLen > 16)
            return 1;
    
        seed.SEED_KeySched(mKey, rKey);
    
        seed.SEED_Encrypt(H, H, rKey);
    
        makeM8(M8, H);
    
        if (nonceLen == 12)
        {
            Byte2Word(GCTR_in, nonce, 0, nonceLen);
    
            GCTR_in[3] = 1;
            
            seed.SEED_Encrypt(Z, GCTR_in, rKey);
        }
        else
        {
            for (i = 0; i < nonceLen; i += BLOCK_SIZE_SEED)
            {
                ZERO128(tmp);
    
                if ((nonceLen - i) < 16)
                    Byte2Word(tmp, nonce, i, nonceLen - i);
                else
                    Byte2Word(tmp, nonce, i, BLOCK_SIZE_SEED);
                
                GHASH_8BIT(GCTR_in, tmp, M8, R8);
            }
    
            ZERO128(tmp);
            tmp[3] = (nonceLen << 3);
    
            GHASH_8BIT(GCTR_in, tmp, M8, R8);
    
            seed.SEED_Encrypt(Z, GCTR_in, rKey);
        }
    
        for (i = 0; i < ptLen; i += BLOCK_SIZE_SEED)
        {
            ZERO128(tmp);
    
            INCREASE(GCTR_in);
    
            seed.SEED_Encrypt(GCTR_out, GCTR_in, rKey);
    
            if ((ptLen - i) < 16)
            {
                Byte2Word(tmp, pt, i, ptLen - i);
                XOR128(GCTR_out, GCTR_out, tmp);
                Word2Byte(ct, i, GCTR_out, ptLen - i);
            }
            else
            {
                Byte2Word(tmp, pt, i, BLOCK_SIZE_SEED);
                XOR128(GCTR_out, GCTR_out, tmp);
                Word2Byte(ct, i, GCTR_out, BLOCK_SIZE_SEED);
            }
        }
    
        for (i = 0; i < aadLen; i += BLOCK_SIZE_SEED)
        {
            ZERO128(GHASH_in);
    
            if ((aadLen - i) < 16)
                Byte2Word(GHASH_in, aad, i, aadLen - i);
            else
                Byte2Word(GHASH_in, aad, i, BLOCK_SIZE_SEED);
    
            GHASH_8BIT(GHASH_out, GHASH_in, M8, R8);
        }
    
        for (i = 0; i < ptLen; i += BLOCK_SIZE_SEED)
        {
            ZERO128(GHASH_in);
    
            if ((ptLen - i) < 16)
                Byte2Word(GHASH_in, ct, i, ptLen - i);
            else
                Byte2Word(GHASH_in, ct, i, BLOCK_SIZE_SEED);
    
            GHASH_8BIT(GHASH_out, GHASH_in, M8, R8);
        }
    
        ZERO128(GHASH_in);
    
        GHASH_in[1] ^= aadLen << 3;
        GHASH_in[3] ^= ptLen << 3;
    
        GHASH_8BIT(GHASH_out, GHASH_in, M8, R8);
    
        XOR128(GHASH_out, GHASH_out, Z);
    
        Word2Byte(ct, ptLen, GHASH_out, macLen);

        return ptLen + macLen;
    }
    
    public int SEED_GCM_Decryption(
        byte[] pt,
        byte[] ct, int ctLen,
        int macLen,
        byte[] nonce, int nonceLen,
        byte[] aad, int aadLen,
        byte[] mKey)
    {
        int[] rKey = new int[100];
        int[] H = new int[4];
        int[] Z = new int[4];
        int[] tmp = new int[8];
        int[] GCTR_in = new int[4];
        int[] GCTR_out = new int[4];
        int[] GHASH_in = new int[4];
        int[] GHASH_out = new int[4];
        byte[] MAC = new byte[16];
        int[][] M8 = new int[256][4];
        int i = 0, j = 0;
        KISA_SEED seed = new KISA_SEED();
    
        if (macLen > 16)
            return 1;
    
        seed.SEED_KeySched(mKey, rKey);
    
        seed.SEED_Encrypt(H, H, rKey);
    
        makeM8(M8, H);
    
        if (nonceLen == 12)
        {
            Byte2Word(GCTR_in, nonce, 0, nonceLen);
    
            GCTR_in[3] = 1;
            
            seed.SEED_Encrypt(Z, GCTR_in, rKey);
        }
        else
        {
            for (i = 0; i < nonceLen; i += BLOCK_SIZE_SEED)
            {
                ZERO128(tmp);
    
                if ((nonceLen - i) < 16)
                    Byte2Word(tmp, nonce, i, nonceLen - i);
                else
                    Byte2Word(tmp, nonce, i, BLOCK_SIZE_SEED);
                
                GHASH_8BIT(GCTR_in, tmp, M8, R8);
            }
    
            ZERO128(tmp);
            tmp[3] = (nonceLen << 3);
    
            GHASH_8BIT(GCTR_in, tmp, M8, R8);
            
            seed.SEED_Encrypt(Z, GCTR_in, rKey);
        }
    
        for (i = 0; i < ctLen - macLen; i += BLOCK_SIZE_SEED)
        {
            ZERO128(tmp);
    
            INCREASE(GCTR_in);
    
            seed.SEED_Encrypt(GCTR_out, GCTR_in, rKey);
    
            if ((ctLen - macLen - i) < 16)
            {
                Byte2Word(tmp, ct, i, ctLen - macLen - i);
                XOR128(GCTR_out, GCTR_out, tmp);
                Word2Byte(pt, i, GCTR_out, ctLen - macLen - i);
            }
            else
            {
                Byte2Word(tmp, ct, i, BLOCK_SIZE_SEED);
                XOR128(GCTR_out, GCTR_out, tmp);
                Word2Byte(pt, i, GCTR_out, BLOCK_SIZE_SEED);
            }
        }
    
        for (i = 0; i < aadLen; i += BLOCK_SIZE_SEED)
        {
            ZERO128(GHASH_in);
    
            if ((aadLen - i) < 16)
                Byte2Word(GHASH_in, aad, i, aadLen - i);
            else
                Byte2Word(GHASH_in, aad, i, BLOCK_SIZE_SEED);
    
            GHASH_8BIT(GHASH_out, GHASH_in, M8, R8);
        }
    
        for (i = 0; i < ctLen - macLen; i += BLOCK_SIZE_SEED)
        {
            ZERO128(GHASH_in);
    
            if ((ctLen - macLen - i) < 16)
                Byte2Word(GHASH_in, ct, i, ctLen - macLen - i);
            else
                Byte2Word(GHASH_in, ct, i, BLOCK_SIZE_SEED);
    
            GHASH_8BIT(GHASH_out, GHASH_in, M8, R8);
        }
    
        ZERO128(GHASH_in);
    
        GHASH_in[1] = aadLen << 3;
        GHASH_in[3] = (ctLen - macLen) << 3;
    
        GHASH_8BIT(GHASH_out, GHASH_in, M8, R8);
    
        XOR128(GHASH_out, GHASH_out, Z);
    
        Word2Byte(MAC, 0, GHASH_out, macLen);
    
        for (i = 0; i < macLen; i++)
        {
            if (ct[ctLen - macLen + i] != MAC[i])
            {
                for (j = 0; j < ctLen - macLen;j++)
                    pt[j] = 0;
                
                return 1;
            }
        }

        return ctLen - macLen;
    }

    public static void main(String[] args) throws IOException
    {
        if(args.length !=4){
			throw new IllegalArgumentException("Usage: java KISA_SEED_ECB <key> <input_file> <output_file> <mode> ");
		}


		// User secret key		
		// 파이썬으로부터 전달받은 키 값
        String keyString = args[0];
		Path inputFilePath = Path.of(args[1]);
		Path outputFilePath = Path.of(args[2]);
		int mode = Integer.parseInt(args[3]);
        byte[] pbUserKey = keyString.getBytes(StandardCharsets.UTF_8);

        // 16바이트로 패딩 처리
        if (pbUserKey.length < 16) {
            pbUserKey = Arrays.copyOf(pbUserKey, 16);
        } else if (pbUserKey.length > 16) {
            throw new IllegalArgumentException("Key length should be 16 bytes or less.");
        }
        byte[] in = new byte[160];
        byte[] out1 = new byte[160];
        byte[] out2 = new byte[160];
        byte[] nonce = new byte[160];
        byte[] aad = new byte[160];

        KISA_SEED_GCM seed_gcm = new KISA_SEED_GCM();
    
        int inLen = 0, out1Len = 0, out2Len = 0, nonceLen = 0, aadLen = 0, macLen = 16;

        nonceLen = asc2hex(nonce, "75E2534A34F65F85A28E318A");
        aadLen = asc2hex(aad, "9DEA72038744675F026877F23C1F6056F77700BA38ADB2E33F50DB71BCA4C06440459BDEF20CED2A833615FE64C322FD361DE68082FA4B96AA83EB4A1FB6DA24D509C6F2F45043C7D1E060451CF57E185B5162C39626889F5436BA20C739E25B447F1DC5F6D6103ED2AE7F4ECD7B1BAE4D5B9C0ADEF9100527B1737E1CF57F11");
        inLen = asc2hex(in, "6702C72AA04D49BDD4269D672A6C369AD9C72CDCDF8D92CBF6E2045EC4247F6D52867574BFFA2194365519DA1DAD22C48F0647010D2E2D7970E6A18D224273A08E5387D6D503291BC33FA168015C07418CB35983658FCB5C8B4A5E9B26B2B42A05B123D84A2E085C642E5E973E3F8F1AB61689E85177157D2D55640F373BEB13");

    	macLen = 12;
        
        if(mode == 0){
			String plainText = Files.readString(inputFilePath, StandardCharsets.UTF_8);
			byte[] pbData = plainText.getBytes(StandardCharsets.UTF_8);
            String hexString = bytesToHex(pbData);

			System.out.print("\n");
			System.out.print("[ SEED GCM 모드 암호화 ]"+"\n");
			System.out.print("\n\n");
			
			System.out.print("Key\t\t: ");
			for (int i=0; i<16; i++)	System.out.print(Integer.toHexString(0xff&pbUserKey[i])+" ");
			System.out.println("\n");
            System.out.println("encData\t: \n");

			try (var fos = Files.newBufferedWriter(outputFilePath, StandardCharsets.UTF_8, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)) {
				for (int i = 0; i < hexString.length(); i += 256) {
					int length = Math.min(256, hexString.length() - i);
                    String part = hexString.substring(i, i + length);
                    inLen = asc2hex(in, part);
                    System.out.println(inLen);
                    out1Len = seed_gcm.SEED_GCM_Encryption(out1, in, inLen, macLen, nonce, nonceLen, aad, aadLen, pbUserKey);
                    
                    int j = 0;
                    for (j = 0; j < out1Len; j++)
                    {
                        if ((j & 0x0F) == 0)
                            System.out.println("");

                        System.out.printf(" %02X", out1[j]);
                        fos.write(String.format("%02X ", out1[j]));
                    }
                    System.out.println("");
				}
			}

		}else{
			System.out.print("\n");
			System.out.print("[ SEED GCM 모드 복호화 ]"+"\n");
			System.out.print("\n\n");
			
			System.out.print("Key\t\t: ");
			for (int i=0; i<16; i++)	System.out.print(Integer.toHexString(0xff&pbUserKey[i])+" ");
			System.out.print("\n");

			// 암호화된 데이터를 읽어와서 바이트 배열로 변환
			String[] encryptedHexStrings = Files.readString(inputFilePath, StandardCharsets.UTF_8).split("\\s+");
            byte[] encryptedBytes = new byte[encryptedHexStrings.length];

			for (int i = 0; i < encryptedHexStrings.length; i++) {
				encryptedBytes[i] = (byte) Integer.parseInt(encryptedHexStrings[i], 16);
			}
	
			// 복호화 과정
            byte [] decryptedData = new byte[encryptedBytes.length];
            int decryptedLength = 0;


			try (var fos = Files.newBufferedWriter(outputFilePath, StandardCharsets.UTF_8, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)) {
				for (int i = 0; i < encryptedBytes.length; i += 140) {
					int length = Math.min(140, encryptedBytes.length - i);
                    byte[] block = Arrays.copyOfRange(encryptedBytes, i, i + length);
                    out2Len = seed_gcm.SEED_GCM_Decryption(out2, block, length, macLen, nonce, nonceLen, aad, aadLen, pbUserKey);
                    System.arraycopy(out2, 0, decryptedData, decryptedLength, out2Len);
                    decryptedLength += out2Len;
				}
                String decryptedText = new String(decryptedData, 0, decryptedLength, StandardCharsets.UTF_8);
                System.out.println(decryptedText);
                fos.write(decryptedText);
			}
		}

    }

    private static int asc2hex(byte[] dst, String src)
    {
        byte temp = 0x00, hex = 0;
        int i = 0;
    
        for (i = 0; i < src.length(); i++)
        {
            temp = 0x00;
            hex = (byte)src.charAt(i);
    
            if ((hex >= 0x30) && (hex <= 0x39))
                temp = (byte)(hex - 0x30);
            else if ((hex >= 0x41) && (hex <= 0x5A))
                temp = (byte)(hex - 0x41 + 10);
            else if ((hex >= 0x61) && (hex <= 0x7A))
                temp = (byte)(hex - 0x61 + 10);
            else
                temp = 0x00;
            
            if ((i & 1) == 1)
                dst[i >> 1] ^= temp & 0x0F;
            else
                dst[i >> 1] = (byte)(temp << 4);
        }
    
        return ((i + 1) / 2);
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xFF & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }
}