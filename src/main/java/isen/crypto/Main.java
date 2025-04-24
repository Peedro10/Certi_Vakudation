package isen.crypto;

import java.io.File;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

/**
 * Classe principale du programme de validation de certificats
 * Arguments simplifiés : [FORMAT] [CHEMIN]
 * Exemple : DER src/main/resources/certificates/valid/monCertificat.crt
 */
public class Main {

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        
        try {
            if (args.length >= 1) {
                // Mode avec arguments simplifiés
                String format = args[0];
                
                // Reconstruire le chemin du certificat à partir des arguments restants
                // pour gérer les chemins avec espaces
                StringBuilder pathBuilder = new StringBuilder();
                for (int i = 1; i < args.length; i++) {
                    if (i > 1) {
                        pathBuilder.append(" ");
                    }
                    pathBuilder.append(args[i]);
                }
                
                String certPath = pathBuilder.length() > 0 ? pathBuilder.toString() : null;
                
                if (certPath == null) {
                    System.out.print("Chemin du certificat à analyser: ");
                    certPath = scanner.nextLine();
                }
                
                processCertificate(certPath, format);
            } else {
                // Mode interactif
                boolean running = true;
                
                while (running) {
                    System.out.println("\n===== VALIDATION DE CERTIFICATS X.509 =====");
                    System.out.println("1. Analyser un certificat");
                    System.out.println("2. Valider une chaîne de certificats");
                    System.out.println("3. Quitter");
                    System.out.print("Votre choix: ");
                    
                    String choice = scanner.nextLine();
                    
                    switch (choice) {
                        case "1":
                            System.out.print("Format du certificat (DER/PEM): ");
                            String format = scanner.nextLine();
                            
                            if (!format.equalsIgnoreCase("DER") && !format.equalsIgnoreCase("PEM")) {
                                System.out.println("Format non supporté. Utilisez DER ou PEM.");
                                continue;
                            }
                            
                            System.out.print("Chemin du certificat à analyser: ");
                            String certPath = scanner.nextLine();
                            
                            processCertificate(certPath, format);
                            break;
                            
                        case "2":
                            System.out.print("Format des certificats (DER/PEM): ");
                            String chainFormat = scanner.nextLine();
                            
                            if (!chainFormat.equalsIgnoreCase("DER") && !chainFormat.equalsIgnoreCase("PEM")) {
                                System.out.println("Format non supporté. Utilisez DER ou PEM.");
                                continue;
                            }
                            
                            System.out.println("Entrez les chemins des certificats de la chaîne (du certificat feuille au racine)");
                            System.out.println("Tapez 'done' quand vous avez terminé");
                            
                            List<X509Certificate> certificateChain = new ArrayList<>();
                            int certIndex = 1;
                            
                            while (true) {
                                System.out.print("Certificat #" + certIndex + " (ou 'done'): ");
                                String chainCertPath = scanner.nextLine();
                                
                                if (chainCertPath.equalsIgnoreCase("done")) {
                                    break;
                                }
                                
                                try {
                                    X509Certificate cert = CertificateUtils.loadCertificate(chainCertPath, chainFormat);
                                    certificateChain.add(cert);
                                    certIndex++;
                                } catch (Exception e) {
                                    System.out.println("Erreur lors du chargement du certificat: " + e.getMessage());
                                }
                            }
                            
                            if (certificateChain.isEmpty()) {
                                System.out.println("Aucun certificat dans la chaîne.");
                                continue;
                            }
                            
                            CertificateChainValidator chainValidator = new CertificateChainValidator();
                            boolean isChainValid = chainValidator.validateChainWithRevocation(certificateChain, true);
                            
                            if (isChainValid) {
                                System.out.println("\nRésultat: La chaîne de certificats est valide.");
                            } else {
                                System.out.println("\nRésultat: La chaîne de certificats n'est pas valide.");
                            }
                            break;
                            
                        case "3":
                            running = false;
                            System.out.println("Au revoir!");
                            break;
                            
                        default:
                            System.out.println("Option non reconnue.");
                    }
                }
            }
        } catch (Exception e) {
            System.out.println("Une erreur s'est produite: " + e.getMessage());
            e.printStackTrace();
        } finally {
            scanner.close();
        }
    }
    
    /**
     * Traite un certificat en l'analysant et en affichant ses informations
     * 
     * @param certPath Chemin du certificat
     * @param format Format du certificat (DER ou PEM)
     */
    private static void processCertificate(String certPath, String format) {
        try {
            // Vérifier le format
            if (!format.equalsIgnoreCase("DER") && !format.equalsIgnoreCase("PEM")) {
                System.out.println("Format non supporté: " + format + ". Utilisez DER ou PEM.");
                return;
            }
            
            // Vérifier que le chemin n'est pas vide
            if (certPath == null || certPath.trim().isEmpty()) {
                System.out.println("Erreur: Aucun chemin de certificat spécifié.");
                return;
            }
            
            // Nettoyer le chemin (suppression des espaces en début/fin)
            certPath = certPath.trim();
            
            // Vérifier que le fichier existe
            File certFile = new File(certPath);
            if (!certFile.exists() || !certFile.isFile()) {
                System.out.println("Erreur: Le fichier spécifié n'existe pas ou n'est pas accessible: " + certPath);
                
                // Suggérer des chemins alternatifs possibles
                String fileName = CertificateUtils.extractFileName(certPath);
                System.out.println("Avez-vous essayé ces chemins ?");
                System.out.println("- src/main/resources/certificates/valid/" + fileName);
                System.out.println("- src/main/resources/certificates/invalid/" + fileName);
                System.out.println("- src/main/resources/certificates/chain/" + fileName);
                return;
            }
            
            // Charger le certificat
            X509Certificate cert = CertificateUtils.loadCertificate(certPath, format);
            String fileName = CertificateUtils.extractFileName(certPath);
            
            // Afficher les informations du certificat
            System.out.println("\n===== INFORMATIONS DU CERTIFICAT =====");
            CertificateUtils.displayCertificateInfo(cert, fileName);
            
            // Utiliser CertificateValidator pour effectuer les vérifications
            CertificateValidator validator = new CertificateValidator();
            boolean isValid = validator.validateCertificate(cert);
            
            if (isValid) {
                System.out.println("\nRésultat: Le certificat est valide.");
            } else {
                System.out.println("\nRésultat: Le certificat n'est pas valide.");
            }
            
        } catch (Exception e) {
            System.out.println("Impossible de traiter le certificat: " + e.getMessage());
            e.printStackTrace();
        }
    }
}