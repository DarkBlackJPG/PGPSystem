package pgp;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.*;
import java.util.Date;
import java.util.Iterator;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.bc.*;
import org.bouncycastle.openpgp.operator.jcajce.*;
import org.bouncycastle.util.io.Streams;
//
//import sun.misc.BASE64Decoder;

//import sun.misc.BASE64Encoder;
/**
 * Provides methods to encrypt, decrypt, sign and verify signature using PGP keypairs
 */
@Deprecated
public class PGPEncrytionUtil {
    public static void signEncryptMessage(InputStream in, OutputStream out, PGPPublicKey publicKey, PGPPrivateKey secretKey, SecureRandom rand) throws Exception {
        out = new ArmoredOutputStream(out);

        PGPEncryptedDataGenerator encryptedDataGenerator = new PGPEncryptedDataGenerator(
                new BcPGPDataEncryptorBuilder(PGPEncryptedData.AES_256).setWithIntegrityPacket(true).setSecureRandom(rand));
        encryptedDataGenerator.addMethod(new BcPublicKeyKeyEncryptionMethodGenerator(publicKey));

        OutputStream compressedOut = new PGPCompressedDataGenerator(PGPCompressedData.ZIP)
                .open(encryptedDataGenerator.open(out, 4096), new byte[4096]);

        PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(
                        new BcPGPContentSignerBuilder(publicKey.getAlgorithm(),
                                HashAlgorithmTags.SHA512));
        signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, secretKey);
        signatureGenerator.generateOnePassVersion(true)
                          .encode(compressedOut);

        OutputStream finalOut = new PGPLiteralDataGenerator()
                            .open(compressedOut, PGPLiteralData.BINARY,
                            "", new Date(), new byte[4096]);

        byte[] buf = new byte[4096];
        int len;
        while ((len = in.read(buf)) > 0) {
            finalOut.write(buf, 0, len);
            signatureGenerator.update(buf, 0, len);
        }

        finalOut.close();
        in.close();
        signatureGenerator.generate().encode(compressedOut);
        compressedOut.close();
        encryptedDataGenerator.close();
        out.close();
    }

    public static void decryptVerifyMessage(InputStream in, OutputStream out, PGPPrivateKey secretKey, PGPPublicKey publicKey) throws Exception {
        in = new ArmoredInputStream(in);

        PGPObjectFactory pgpF = new PGPObjectFactory(in, new JcaKeyFingerprintCalculator());
        PGPEncryptedDataList enc = (PGPEncryptedDataList) pgpF.nextObject();

        PGPObjectFactory plainFact = new PGPObjectFactory(((PGPPublicKeyEncryptedData) enc.getEncryptedDataObjects().next()).getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(secretKey)), new JcaKeyFingerprintCalculator());

        Object message = null;

        PGPOnePassSignatureList onePassSignatureList = null;
        PGPSignatureList signatureList = null;
        PGPCompressedData compressedData = null;

        message = plainFact.nextObject();
        ByteArrayOutputStream actualOutput = new ByteArrayOutputStream();

        while (message != null) {
            System.out.println(message.toString());
            if (message instanceof PGPCompressedData) {
                compressedData = (PGPCompressedData) message;
                plainFact = new PGPObjectFactory(compressedData.getDataStream(), new JcaKeyFingerprintCalculator());
                message = plainFact.nextObject();
                System.out.println(message.toString());
            }

            if (message instanceof PGPLiteralData) {
                Streams.pipeAll(((PGPLiteralData) message).getInputStream(), actualOutput);
            } else if (message instanceof PGPOnePassSignatureList) {
                onePassSignatureList = (PGPOnePassSignatureList) message;
            } else if (message instanceof PGPSignatureList) {
                signatureList = (PGPSignatureList) message;
            } else {
                throw new PGPException("message unknown message type.");
            }
            message = plainFact.nextObject();
        }
        actualOutput.close();
        byte[] output = actualOutput.toByteArray();
        if (onePassSignatureList == null || signatureList == null) {
            throw new PGPException("Poor PGP. Signatures not found.");
        } else {

            for (int i = 0; i < onePassSignatureList.size(); i++) {
                PGPOnePassSignature ops = onePassSignatureList.get(0);
                System.out.println("verifier : " + ops.getKeyID());
                if (publicKey != null) {
                    ops.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), publicKey);
                    ops.update(output);
                    PGPSignature signature = signatureList.get(i);
                    if (ops.verify(signature)) {
                        Iterator<?> userIds = publicKey.getUserIDs();
                        while (userIds.hasNext()) {
                            String userId = (String) userIds.next();
                            System.out.println("Signed by " + userId);
                        }
                        System.out.println("Signature verified");
                    } else {
                        throw new SignatureException("Signature verification failed");
                    }
                }
            }

        }

        out.write(output);
        out.flush();
        out.close();
    }

    public static void main(String args[]) {
        Security.insertProviderAt(new BouncyCastleProvider(), 0);
        byte inBytes[] = "The quick brown fox jumps over the lazy dog.".getBytes();

        try {
            SecureRandom rand = new SecureRandom();

            RSAKeyPairGenerator kpg = new RSAKeyPairGenerator();
            kpg.init(new RSAKeyGenerationParameters(BigInteger.valueOf(0x10001), rand, 1024, 90));

            BcPGPKeyPair sender = new BcPGPKeyPair(PGPPublicKey.RSA_GENERAL, kpg.generateKeyPair(), new Date());
            BcPGPKeyPair recip = new BcPGPKeyPair(PGPPublicKey.RSA_GENERAL, kpg.generateKeyPair(), new Date());

            ByteArrayOutputStream sendMessage = new ByteArrayOutputStream();
            ByteArrayOutputStream recvMessage = new ByteArrayOutputStream();
            signEncryptMessage(new ByteArrayInputStream(inBytes), sendMessage, recip.getPublicKey(), sender.getPrivateKey(), rand);

            System.out.println(sendMessage.toString());

            decryptVerifyMessage(new ByteArrayInputStream(sendMessage.toByteArray()), recvMessage, recip.getPrivateKey(), sender.getPublicKey());

            System.out.println(recvMessage.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
