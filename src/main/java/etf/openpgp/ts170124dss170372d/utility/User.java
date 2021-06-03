package etf.openpgp.ts170124dss170372d.utility;

public class User {
    private static User userInstance;
    private boolean isLoggedIn;
    private String name;
    private String email;
    private String password;

    private User() {
        isLoggedIn = false;
        name = null;
        email = null;
        password = null;
    }

    public String getName() {
        return name;
    }
    public String getEmail() {
        return email;
    }
    public String getPassword() {
        return password;
    }
    public static User getUserInstance() {
        if(userInstance == null) {
            userInstance = new User();
        }

        return  userInstance;
    }

    public static void loginUser(String name, String email, String password) {
        getUserInstance();
        userInstance.isLoggedIn = true;
        userInstance.email = email;
        userInstance.name = name;
        userInstance.password = password;
    }
}
