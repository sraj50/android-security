# android-security

This simple app demonstrates the security features of Android Java-based application.

The Android Application is uses either the default or a custom made Keystore in order to digitally signed a text message that is provided by the user. The
user is capable of choosing the Java keystore that he wants to use as long as it is already stored in some common Android folder.

The Android Application consists of two Activities, a public one called `PrivateUserActivity` and a private one called `PrivateActivity`. When the application start, the Public
activity (`PrivateUserActivity`) is loaded. The `PrivateUserActivity` lets the user to write the path where a custom keystore is going to be used. There is also a text field where the user can write the pass-
word that is needed in order to correctly open the keystore.

The `PrivateActivity` was implemented such that:
- it collects and processes the information coming from `PrivateUserActivity`
- it extracts from the keystore the information regarding the keys and certificates and shows in the textview the key aliases, the certificate type and the cipher that is been used.
- when the user places in the textbox shown in the Figure 1 one of the key alias and has added a text in the other textbox (also shown in the figure 1) if the "Return Result" button is pressed, then the provided user text is digitally signed using the keys in the chosen alias.
- the provided digital signature is returned to `PrivateActivity` and is printed in the appl screen using the Toast class (see relevant code inside the provided Android project)
