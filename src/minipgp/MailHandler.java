package minipgp;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
import java.util.Properties;
import javax.mail.*;
/**
 *
 * @author Leonardo
 */
public class MailHandler {
    
    public void receiveMail(String protocol){
        Folder folder = null;
        Store store;
        String username = "dozeer@gmail.com";
        String password = "";
        String server = "imap.gmail.com";
        try {
            Properties props = System.getProperties();
            props.setProperty("mail.store.protocol", protocol);
            Session session = Session.getDefaultInstance(props, null);
            store = session.getStore();
            store.connect(server, username, password);
            Folder[] folders = store.getUserNamespaces("dozeer");
            for(Folder f : folders){
                System.out.println(f);
            }
        } catch (NoSuchProviderException e) {
        } catch (MessagingException e) {
            System.err.println(e.getMessage());
        }
    }
}
