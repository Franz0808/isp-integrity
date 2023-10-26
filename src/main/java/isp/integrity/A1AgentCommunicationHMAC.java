package isp.integrity;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.MessageDigest;

/**
 * TASK:
 * Assuming Alice and Bob know a shared secret key, provide integrity to the channel
 * using HMAC implemted with SHA256. Then exchange ten messages between Alice and Bob.
 * <p>
 * https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html
 */
public class A1AgentCommunicationHMAC {
    public static void main(String[] args) throws Exception {
        /*
         * Alice and Bob share a secret session key that will be
         * used for hash based message authentication code.
         */
        final Key key = KeyGenerator.getInstance("HmacSHA256").generateKey();

        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                final String text = "I hope you get this message intact. Kisses, Alice.";
                

                final Mac alice_Mac = Mac.getInstance("HmacSHA256");
                alice_Mac.init(key);
                
                for (int i = 0; i < 10; i++) {

                    final byte [] pt = text.getBytes(StandardCharsets.UTF_8);
                    final byte[] tag1 = alice_Mac.doFinal(pt);     
            
                    send("bob", tag1);
                    send("bob",pt);

                    byte[] tag3 = receive("bob");
                    byte[] pt2 = receive("bob");

                    final byte[] tag4 = alice_Mac.doFinal(pt2);
                    System.out.println(new String(pt2));
                    System.out.println(MessageDigest.isEqual(tag3, tag4));
                }

            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                
                final String answer = "I did. Kisses, Bob.";

                final Mac bob_Mac = Mac.getInstance("HmacSHA256");
                bob_Mac.init(key);

                for (int i = 0; i < 10; i++) {
                    
                    byte[] tag1 = receive("alice");
                    byte[] pt = receive("alice");

                    final byte[] tag2 = bob_Mac.doFinal(pt);
                    System.out.println(new String(pt));
                    System.out.println(MessageDigest.isEqual(tag1, tag2));

                    final byte [] pt2 = answer.getBytes(StandardCharsets.UTF_8);
                    final byte[] tag3 = bob_Mac.doFinal(pt2);     
            
                    send("alice", tag3);
                    send("alice",pt2);
                }
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
