/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package minipgp;

import java.io.File;
import java.io.FileFilter;
import java.io.FilenameFilter;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;
import minipgp.gui.MainWindow;

/**
 *
 * @author leonardo
 */
public class Main {
    
    public static final String msgDir = "Messages/";
    public static final String pubKeyDir = "Public Keys/";
    public static final String priKeyDir = "Private Keys/";

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        // Criar diretórios do programa, caso não existam
        File m, pubK, priK;
        m = new File(msgDir);
        pubK = new File(pubKeyDir);
        priK = new File(priKeyDir);
        if(!m.exists()){
            m.mkdir();
        }
        if(!pubK.exists()){
            pubK.mkdir();
        }
        if(!priK.exists()){
            priK.mkdir();
        }
        
        new MainWindow();
//        Message msg = new Message("dozeer@gmail.com", "leonardo.filipe@live.com", "top kek lol\nfagt.");
//        File f = new File("Messages/test.xml");
//        PGPMethods.generateKeyPair("dozeer@gmail.com");
//        msg.saveMessageToXML(f, "stormageddon123", PGPMethods.getPrivateKey("dozeer@gmail.com"), true);
//        Message file = Message.readMessageFromXML(f);
//        file.decompressMessage();
//        file.decryptMessage("stormageddon123");
//        System.out.println(file.verifySignature(PGPMethods.getPublicKey(file.getSender())));
//        System.out.println(file.getMessage());
    }
    
    public static void saveMessage(Message msg, String encryptionPassword,
            boolean signature, boolean compression) throws Exception{
        // Garantir a existência do diretório Messages/<destinatário>/<remetente>/
        // para armazenar a mensagem
        File f = new File(getMessagePath(msg));
        f.mkdirs();
        
        // Arquivo a ser criado para a mensagem
        f = new File(getMessagePath(msg) + getMessageFilename());
        PrivateKey priK = null;
        if(signature){
            priK = PGPMethods.getPrivateKey(msg.getSender());
            if(priK == null){
                throw new Exception(
                        "Não há chave privada armazenada para '"
                                + msg.getSender() + "'");
            }
        }
        msg.saveMessageToXML(f, encryptionPassword, priK, compression);
    }
    
    private static String getMessagePath(Message msg){
        String sender = msg.getSender();
        String recipient = msg.getRecipient();
        return msgDir + recipient + "/" + sender + "/";
    }
    
    // Gera o nome do arqivo da mensagem baseado no horário atual
    private static String getMessageFilename(){
        Calendar c = Calendar.getInstance();
        return "("
                + c.get(Calendar.DATE) + "-"
                + c.get(Calendar.MONTH) + "-"
                + c.get(Calendar.YEAR)
                + ")("
                + c.get(Calendar.HOUR_OF_DAY) + "-"
                + c.get(Calendar.MINUTE) + "-"
                + c.get(Calendar.SECOND) + ")"
                + ".xml";
    }
    
    public static String[] getPublicKeyList(){
        List<String> filenames = getXMLList(pubKeyDir);
        return filenames.toArray(new String[filenames.size()]);
    }
    
    public static String[] getPrivateKeyList(){
        List<String> filenames = getXMLList(priKeyDir);
        return filenames.toArray(new String[filenames.size()]);
    }
    
    private static List<String> getXMLList(String directoryPath){
        File pubKDir = new File(directoryPath);
        File[] files = pubKDir.listFiles(new FilenameFilter() {

            @Override
            public boolean accept(File file, String name) {
                System.out.println(file.getName());
                return name.endsWith(".xml");
            }
        });
        ArrayList<String> filenames = new ArrayList<>();
        for(File f: files){
            String filename = f.getName();
            filenames.add(filename.substring(0, filename.length() - ".xml".length()));
        }
        return filenames;
    }
    
    public static File[] getInboxList(){
        File msgs = new File(msgDir);
        File[] inboxes = msgs.listFiles(new FileFilter() {

            @Override
            public boolean accept(File file) {
                return file.isDirectory();
            }
        });
        return inboxes;
    }
    
    public static File[] getSendersList(File inbox){
        return inbox.listFiles(new FileFilter() {

            @Override
            public boolean accept(File file) {
                return file.isDirectory();
            }
        });
    }
    
    public static File[] getMessageList(File inboxSender){
        return inboxSender.listFiles(new FilenameFilter() {

            @Override
            public boolean accept(File file, String name) {
                return name.endsWith(".xml");
            }
        });
    }
}
