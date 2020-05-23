import java.util.Scanner;

public class Main {

    public static void main(String[] args) throws Exception {
        Scanner sc = new Scanner(System.in);

        System.out.println("1 - Client\n2 - Server");
        System.out.print("Option: ");
        int choice = sc.nextInt();
        sc.nextLine(); // Die Newline von der Wahl bleibt sonst bestehen und fällt durch

        if(choice == 1) {
            System.out.print("IP: ");
            String ip = sc.nextLine();
            System.out.print("Port: ");
            int port = sc.nextInt();
            new ChatClient(ip, port);
        } else if(choice == 2) {
            System.out.print("Port: ");
            int port = sc.nextInt();
            new ChatServer(port);
        }
    }

}
