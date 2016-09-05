package acertum.secureRequestHandler;

public class Test {
    public static void main(String args[]) {
        int folio = 1000 + (int)(Math.random() * 1000);
        int sucursal = 10000 + (int)(Math.random() * 1000);
        SecureRequestHandler.getInstance().requestBarCode(folio, sucursal);
    }
}
