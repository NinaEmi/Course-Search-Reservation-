#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <ctime>
#include <chrono>
#include <iomanip>
#include <random>
#include <string>
#include <cmath>

using namespace std;

class InvalidCredentialsException : public exception
{
public:
    const char* what() const noexcept override
    {
        return "Credentiale incorecte!";
    }
};

class InvalidEmailFormatException : public exception
{
public:
    const char* what() const noexcept override
    {
        return "Formatul emailului este incorect!";
    }
};

class WeakPasswordException : public exception
{
public:
    const char* what() const noexcept override
    {
        return "Parola este prea slaba! Parola trebuie sa contina macar un caracter special si sa aiba mai mult de 8 caractere.";
    }
};

class PasswordMismatchException : public exception
{
public:
    const char* what() const noexcept override
    {
        return "Parola repetata nu corespunde!";
    }
};

class CourseNotExisting : public exception
{
public:
    const char* what() const noexcept override
    {
        return "Cursa inexistenta!";
    }
};

class DateInvalid : public exception
{
public:
    const char* what() const noexcept override
    {
        return "Data introdusa nu respecta formatul dd/mm/yyyy!";
    }
};

class CityInvalid : public exception
{
public:
    const char* what() const noexcept override
    {
        return "Orasele trebuie introduse corect, cu litere mari!";
    }
};

class CitySpecialCharacter : public exception
{
public:
    const char* what() const noexcept override
    {
        return "Orasele nu trebuie sa contina caractere speciale!";
    }
};

class DateInPast : public exception
{
public:
    const char* what() const noexcept override
    {
        return "Data introdusa este in trecut!";
    }
};

class CustomCrypt
{
private:
    long long int modulus;

public:
    // Definirea metodelor pentru criptare și decriptare

    long long int generateRandomPrime(long long int lowerBound, long long int upperBound)
    {
        random_device rd;
        mt19937 gen(rd());
        uniform_int_distribution<int> distribution(lowerBound, upperBound);
        long long int randomNumber;

        int i, flag = 1;
        while (flag)
        {
            randomNumber = distribution(gen);
            if (randomNumber > 1)
            {
                flag = 0;
                for (i = 2; i <= sqrt(randomNumber); i++)
                    if (randomNumber % i == 0)
                    {
                        flag = 1;
                        break;
                    }
            }
        }
        return randomNumber;
    }
    long long int gcd(long long int a, long long int b)
    {
        long long int r;
        while (b != 0)
        {
            r = a % b;
            a = b;
            b = r;
        }
        return a;
    }

    // Funcție pentru generarea cheilor RSA
    pair<long long int, long long int> createKeys()
    {
        long long int p = generateRandomPrime(50, 100); // Intervalul pentru numere prime mai mari
        long long int q = generateRandomPrime(100, 150);
        modulus = p * q;
        long long int publicKey = 2;
        long long int phi = (p - 1) * (q - 1);

        while (1)
        {
            if (gcd(publicKey, phi) == 1)
                break;
            publicKey++;
        }

        long long int privateKey = 2;

        while (1)
        {
            if ((privateKey * publicKey) % phi == 1)
                break;
            privateKey++;
        }
        return {publicKey, privateKey};
    }

    // Funcție pentru criptarea mesajului
    long long int encryptMessage(long long int message, int publicKey)
    {
        long long int e = publicKey;
        long long int encryptedText = 1;
        while (e--)
        {
            encryptedText = (encryptedText * message) % modulus;
        }
        return encryptedText;
    }

    // Funcție pentru decriptarea mesajului
    long long int decryptMessage(int encryptedMessage, int privateKey)
    {
        long long int decryptedMessage = 1;
        while (privateKey > 0)
        {
            if (privateKey % 2 == 1)
            {
                decryptedMessage = (decryptedMessage * encryptedMessage) % modulus;
            }
            privateKey = privateKey >> 1;
            encryptedMessage = (encryptedMessage * encryptedMessage) % modulus;
        }
        return decryptedMessage;
    }

    // Funcție pentru criptarea unui șir de caractere
    vector<int> encodeString(const string& password, int publicKey)
    {
        vector<int> encryptedString;
        for (char c : password)
        {
            encryptedString.push_back(encryptMessage(c, publicKey));
        }
        return encryptedString;
    }

    // Funcție pentru decriptarea unui șir de caractere
    string decodeMessage(const vector<int>& encryptedVector, int privateKey)
    {
        string password;
        CustomCrypt cryptManager;
        long long int modulus = cryptManager.modulus; // Modulul este necesar pentru decriptare

        for (long long int encToken : encryptedVector)
        {
            // Decriptăm fiecare caracter utilizând cheia privată și modulul
            long long int decryptedToken = cryptManager.decryptMessage(encToken, privateKey);
            char decryptedChar = static_cast<char>(decryptedToken % modulus); // Conversie înapoi la caracter

            password += decryptedChar;
        }
        return password;
    }

};


class User
{
private:
    string email;
    string password;
    string filename = "users.csv";
    int privateKey;

public:
    // Definirea metodelor pentru utilizator, inclusiv login și înregistrare, verificare daca peroana este sau nu administrator

    User(string email, string password) : email(email), password(password) {}

    string getEmail() const
    {
        return email;
    }

    string getPassword() const
    {
        return password;
    }

    bool loginUser(const string& user, const string& pass)
    {
        ifstream file(filename);
        if (!file.is_open())
        {
            cerr << "Eroare la deschiderea fisierului!\n";
            return false;
        }

        string line;
        CustomCrypt cryptManager;
        while (getline(file, line))
        {
            stringstream ss(line);
            vector<string> tokens;
            string token;
            while (getline(ss, token, ','))
            {
                tokens.push_back(token);
            }

            if (tokens.size() >= 3 && tokens[0] == user)
            {
                // Obține parola criptată din fișier și convertește-o înapoi la vector<int>
                stringstream encryptedPassStream(tokens[1]);
                vector<int> encryptedPass;
                string encryptedToken;
                while (getline(encryptedPassStream, encryptedToken, '/'))
                {
                    encryptedPass.push_back(stoi(encryptedToken));
                }

                // Decriptează parola
                string decryptedPass = cryptManager.decodeMessage(encryptedPass, privateKey);

                // Compară parola decriptată cu cea furnizată de utilizator
                if (decryptedPass == pass)
                {
                    file.close();
                    return true;
                    break;
                }
            }
        }

        file.close();
        return false;
    }

    //verificare daca peroana este sau nu administrator

    bool isAdmin()
    {
        ifstream file(filename);
        if (!file.is_open())
        {
            cerr << "Eroare la deschiderea fisierului!\n";
        }

        string line;
        bool isAdministrator = false;

        while (getline(file, line))
        {
            stringstream ss(line);
            vector<string> tokens;
            string token;
            while (getline(ss, token, ','))
            {
                tokens.push_back(token);
            }


            if ( tokens[5] == "1")
            {
                isAdministrator = true;
                break;
            }
        }
        file.close();
        return isAdministrator;
    }


    void registerUser(const string& user, const string& pass, const string& confirmPass)
    {
        // Verificăm dacă parolele coincid
        if (pass != confirmPass)
        {
            throw PasswordMismatchException();
        }

        // Verificare format email și parolă
        // Dacă sunt probleme, aruncă excepții: InvalidEmailFormatException sau WeakPasswordException
        if (!isValidEmail(user))
        {
            throw InvalidEmailFormatException();
        }

        if (isWeakPassword(pass))
        {
            throw WeakPasswordException();
        }

        ifstream checkIfExists(filename);
        string line;
        while (getline(checkIfExists, line))
        {
            stringstream ss(line);
            vector<string> tokens;
            string token;
            while (getline(ss, token, ','))
            {
                tokens.push_back(token);
            }
            if (tokens.size() == 5 && tokens[0] == user && tokens[1] == pass)
            {
                cerr << "Utilizatorul există deja!\n";
                checkIfExists.close();
                return;
            }
        }
        checkIfExists.close();



        ofstream file(filename, ios::app);
        if (!file.is_open())
        {
            cerr << "Eroare la deschiderea fisierului!\n";
            return;
        }

        CustomCrypt cryptManager;
        pair<long long int, long long int> keys = cryptManager.createKeys();
        int publicKey = keys.first;

// Criptează parola înainte de a o salva în fișier
        vector<int> encryptedPassword = cryptManager.encodeString(pass, publicKey);

// Conversia parolei criptate într-un șir de caractere pentru stocare
        string encryptedPassString;
        for (int encryptedChar : encryptedPassword)
        {
            encryptedPassString += to_string(encryptedChar) + '/';
        }

        file << user << ',' << encryptedPassString << ',' << publicKey << ',' << privateKey << ',' << "0" << endl;

        file.close();
    }

    bool isValidEmail(const string& email)
    {
        // Un format simplu de verificare a email-ului: să conțină '@'
        size_t atPos = email.find('@');
        return atPos != string::npos;
    }

    bool isWeakPassword(const string& password)
    {
        // Verificare simplă pentru o parolă slabă: să aibă mai puțin de 8 caractere
        if (password.length() < 5)
        {
            return true; // Parola are mai puțin de 8 caractere, deci este slabă
        }

        // Verificăm dacă parola conține cel puțin un caracter special
        string specialChars = "!@#$%^&*()_+-=[]{};:,.<>?";
        for (char c : password)
        {
            if (specialChars.find(c) != string::npos)
            {
                return false; // Parola conține cel puțin un caracter special, deci nu e slabă
            }
        }

        return true; // Parola nu conține niciun caracter special
    }

};


class Trip
{
private:
    string index;
    string date;
    string station;
    string destination;
    string tripsFilename = "RegistruCalatori.csv";
    vector<Trip> allTrips;// Vectorul care va conține toate călătoriile

public:
    // Constructorul pentru clasa Trip
    Trip(string index, string station, string destination, string date): index(index), station(station), destination(destination), date(date) {}

    // Metode pentru a accesa informațiile călătoriei
    string getIndex() const
    {
        return index;
    }
    string getStation() const
    {
        return station;
    }
    string getDestination() const
    {
        return destination;
    }
    string getDate() const
    {
        return date;
    }

    void loadTripsFromFile()
    {
        ifstream file(tripsFilename);
        if (!file.is_open())
        {
            cerr << "Eroare la deschiderea fisierului cu curse!\n";
            return;
        }

        string line;
        while (getline(file, line))
        {
            stringstream ss(line);
            vector<string> tokens;
            string token;
            while (getline(ss, token, ','))
            {
                tokens.push_back(token);
            }

            // Construiește obiecte Trip și le adaugă în vectorul allTrips
            if (tokens.size() >= 4)
            {
                Trip trip(tokens[0], tokens[1], tokens[2], tokens[3]);
                allTrips.push_back(trip);
            }
        }
        file.close();
    }

    // Funcție pentru afișarea tuturor călătoriilor
    void displayAllTrips()
    {
        // Iterează prin toate cursele și le afișează
        for (const auto& trip : allTrips)
        {
            cout << "Index: " << trip.getIndex() << " | Station: " << trip.getStation() << "| Destination: " << trip.getDestination() << " | Date: " << trip.getDate() << endl;
        }
    }

    // Funcție pentru căutarea unei călătorii după destinație și stație
    void searchTripByDestination(const string& stationTrip, const string& destinationTrip)
    {
        ifstream file(tripsFilename);
        if (!file.is_open())
        {
            cerr << "Eroare la deschiderea fisierului cu curse!\n";
            return;
        }

        string line;
        while (getline(file, line))
        {
            stringstream ss(line);
            vector<string> tokens;
            string token;
            while (getline(ss, token, ','))
            {
                tokens.push_back(token);
            }

            // Verificăm dacă destinația coincide cu cea căutată
            if (tokens.size() >= 4 && (tokens[1].find(stationTrip) != string::npos) && (tokens[2].find(destinationTrip) != string::npos))
            {
                cout << "Cursa a fost gasita! Data disponibila: " << tokens[3] << endl;
                return;
            }
        }

        cout << "Cursa nu a fost gasita!" << endl;

        file.close();
    }

// Funcție pentru verificarea dacă un șir conține caractere speciale

    bool hasSpecialCharacters(const string& str)
    {
        for (char c : str)
        {
            if (!isalpha(c) && !isspace(c))
            {
                return true; // Dacă găsim un caracter care nu este literă sau spațiu, returnăm true
            }
        }
        return false;
    }

    // Funcție pentru verificarea dacă data este în trecut
    bool isDateInPast(const string& date)
    {
        tm time = {};
        istringstream ss(date);
        ss >> get_time(&time, "%d/%m/%Y");

        if (ss.fail())
        {
            throw DateInvalid(); // Formatul datei este incorect
        }

        auto inputTime = chrono::system_clock::from_time_t(mktime(&time));

        auto currentTime = chrono::system_clock::now();
        auto currentTimeWithoutTime = chrono::system_clock::from_time_t(chrono::system_clock::to_time_t(currentTime));

        return inputTime < currentTimeWithoutTime; // Comparație pentru a verifica dacă data introdusă este în trecut
    }



    // Funcție pentru adăugarea unei călătorii în fișier
    void addTripToFile(const string& index, const string& station, const string& destination, const string& date)
    {
        ofstream file(tripsFilename, ios::app); // Deschidem fișierul pentru adăugarea la sfârșit

        if (!file.is_open())
        {
            cerr << "Eroare la deschiderea fisierului cu curse!\n";
            return;
        }

        //verificam formatul datei dd/mm/year
        if (date.length() != 10 || date[2] != '/' || date[5] != '/')
        {
            throw DateInvalid();
        }

        if (hasSpecialCharacters(station) || hasSpecialCharacters(destination))
        {
            throw CitySpecialCharacter();
        }

        if (isDateInPast(date))
        {
            throw DateInPast();
        }

        // Verificăm dacă orașele sunt introduse corect
        bool validStation = true;
        bool validDestination = true;
        for (char c : station)
        {
            if (!isalpha(c) || !isupper(c))
            {
                validStation = false;
                break;
            }
        }

        for (char c : destination)
        {
            if (!isalpha(c) || !isupper(c))
            {
                validDestination = false;
                break;
            }
        }

        if (!validStation || !validDestination)
        {
            throw CityInvalid();
        }

        // Scriem informațiile despre cursă în fișier, separate prin virgulă
        file << index << ',' << station << ',' << destination << ',' << date << '\n';

        file.close();
    }


    // Funcție pentru ștergerea unei călătorii
    void deleteTrip(const string& indexToDelete)
    {
        ifstream inFile(tripsFilename);
        if (!inFile.is_open())
        {
            cerr << "Eroare la deschiderea fisierului cu curse!\n";
            return;
        }

        string line;
        vector<string> lines;

        // Citirea tuturor liniilor și păstrarea celor care nu trebuie șterse
        while (getline(inFile, line))
        {
            stringstream ss(line);
            vector<string> tokens;
            string token;
            while (getline(ss, token, ','))
            {
                tokens.push_back(token);
            }

            if (tokens.size() >= 4 && tokens[0] != indexToDelete)
            {
                lines.push_back(line);
            }
        }
        inFile.close();

        // Suprascrierea fișierului cu liniile actualizate
        ofstream outFile(tripsFilename);
        if (!outFile.is_open())
        {
            cerr << "Eroare la deschiderea fisierului cu curse!\n";
            return;
        }

        for (const auto& l : lines)
        {
            outFile << l << '\n';
        }
        outFile.close();
    }
};

class Reservation
{
private:
    string username;
    string tripIndex;
    string reservationFile = "Reservari.csv";
    string tripFile = "RegistruCalatori.csv";

public:
    Reservation(const string& username, const string& tripIndex)
        : username(username), tripIndex(tripIndex) {}

    // Funcție pentru verificarea existenței unei călătorii după index
    bool tripExists(const string& indexToCheck)
    {
        ifstream file(tripFile);
        if (!file.is_open())
        {
            cerr << "Eroare la deschiderea fisierului cu curse!\n";
            return false;
        }

        string line;
        while (getline(file, line))
        {
            stringstream ss(line);
            vector<string> tokens;
            string token;
            while (getline(ss, token, ','))
            {
                tokens.push_back(token);
            }

            // Verificarea existenței călătoriei după index
            if (tokens.size() >= 3 && tokens[0] == indexToCheck)
            {
                file.close();
                return true;
            }
        }

        file.close();
        return false;
    }


    // Funcție pentru realizarea unei rezervări
    void makeReservation(const string& username, const string& index)
    {
        ofstream file(reservationFile, ios::app);

        if (!file.is_open())
        {
            cerr << "Eroare la deschiderea fisierului pentru rezervari!\n";
            return;
        }

        // Verificarea dacă călătoria există înainte de a realiza rezervarea
        if(tripExists(index) == true)
        {

            file << username << ',' << index << '\n';
            file.close();
        }
        else cout << "Aceasta calatorie nu exista" << endl;

    }

};

int main()
{
    int choice;
    int choice1;
    Trip tripManager("index", "station", "destination", "date");
    User userManager("email", "password");
    Reservation reservationManager("username", "index");

    cout << "\n--------- WELCOME ---------\n";

    //utilizatorul alege daca interactioneaza ca admin sau utilizator
    //aceasta alegere este verificata mai jos, astefl incat utilizatorul sa nu poata interactiona ca admin

    cout << "Continui ca: \n 1. Utilizator \n 2. Administrator \n Introduceti o optiune: ";
    cin >> choice1;

    if (choice1 == 1)
    {

        //meniu pentru utilizator
        cout << " MENU\n";
        cout << "1. Login\n";
        cout << "2. Inregistrare\n";

        cout << "Introduceti o optiune: ";
        cin >> choice;

        string user, pass, confirmPass;

        try
        {
            switch (choice)
            {
            case 1:
            {
                // Autentificare utilizator

                cout << "Enter Username: ";
                cin >> user;
                cout << "Enter Password: ";
                cin >> pass;

                char choice2;

                if (userManager.loginUser(user, pass) )
                {
                    // Verificarea drepturilor de utilizator
                    if (userManager.isAdmin() == false)
                    {
                        cout << "\n<LOGIN SUCCESSFUL>\n";

                        //dupa ce s-a logat utilizatorul poate rezerva sau cauta o cursa
                        cout << "  MENU TRIPS \n";
                        cout << " A. Cauta o cursa \n";
                        cout << " B. Rezerva o cursa \n";
                        cout << "C. Afiseaza toate calatoriile \n";
                        cout << "Introduceti o optiune ";;

                        cin >> choice2;

                        switch(choice2)
                        {

                        case 'A':
                        {
                            //cautarea unei curse
                            string station;
                            string destination;
                            cout << "Introduceti statia de plecare cautata: ";
                            cin >> station;
                            cout << "Introduceti statia de sosire cautat: ";
                            cin >> destination;
                            tripManager.searchTripByDestination(station, destination);
                            break;
                        }


                        case 'B':
                        {

                            // rezervarea acesteia dupa index
                            string index;
                            string username;
                            cout << "Indexul calatoriei: ";
                            cin >> index;
                            cout << "Username-ul dvs: ";
                            cin >> username;

                            reservationManager.makeReservation(username, index);

                            break;
                        }
                        case 'C':
                        {
                            //afisarea tuturor calatoriilor disonibile
                            tripManager.displayAllTrips();
                            break;
                        }
                        default :
                            cout << "Optiune Invalida";
                            break;

                        }
                    }
                    else
                    {
                        cout << "Nu ai drepturi de utilizator! "<< endl;
                    }
                }
                else
                {

                    throw InvalidCredentialsException();
                }

                break;
            }

            case 2:
            {
                // Înregistrare utilizator
                cout << "Introduceti email-ul: ";
                cin >> user;
                cout << "Introduceti parola: ";
                cin >> pass;
                cout << "Reintroduceti parola: ";
                cin >> confirmPass;

                userManager.registerUser(user, pass, confirmPass);
                cout << "\n<Utilizator Inregistrat cu succes!>\n";

                //dupa ce se inregistreaza, la fel ca la login utilizatorul poate rezerva sau cauta o cursa

                cout << "  MENU TRIPS \n";
                cout << " A. Cauta o cursa \n";
                cout << " B. Rezerva o cursa \n";
                cout <<" C. Afiseaza toate calatoriile \n";
                cout << "Introduceti o optiune ";

                char choice4;

                cin >> choice4;

                switch(choice4)
                {

                case 'A':
                {
                    string station;
                    string destination;
                    cout << "Introduceti statia de plecare cautata: ";
                    cin >> station;
                    cout << "Introduceti statia de sosire cautat: ";
                    cin >> destination;
                    tripManager.searchTripByDestination(station, destination);
                    break;
                }


                case 'B':
                {
                    //rezervarea unei calatorii
                    string index;
                    string username;
                    cout << "Indexul calatoriei: ";
                    cin >> index;
                    cout << "Username-ul dvs: ";
                    cin >> username;

                    reservationManager.makeReservation(username, index);

                    break;
                }
                case 'C':
                {
                    //afisarea tuturor calatoriilor disonibile
                    tripManager.displayAllTrips();
                    break;
                }
                default :
                    cout << "Optiune Invalida";
                    break;

                }
                break;
            }
            default:
                cout << "Optiune invalida\n";
                break;
            }
        } // Capturarea și tratarea excepțiilor în caz de erori
        catch (const InvalidCredentialsException& e)
        {
            cerr << "Eroare la login: " << e.what() << endl;
        }
        catch (const InvalidEmailFormatException& e)
        {
            cerr << "Eroare la inregistrare: " << e.what() << endl;
        }
        catch (const WeakPasswordException& e)
        {
            cerr << "Eroare la inregistrare: " << e.what() << endl;
        }
        catch (const PasswordMismatchException& e)
        {
            cerr << "Eroare la inregistrare: " << e.what() << endl;
        }
    }
    else if (choice1 == 2)
    {
        // Secțiunea pentru administratori

        string adminUser, adminPass;
        cout << "Enter Administrator Username: ";
        cin >> adminUser;
        cout << "Enter Administrator Password: ";
        cin >> adminPass;

        // Verificarea credențialelor administratorului și drepturile de admin
        if (userManager.loginUser(adminUser, adminPass) )
        {

            // se verifica daca este admin
            if(userManager.isAdmin() == true)
            {
                cout << "\n LOGIN SUCCESSFUL \n";

                int choice3;
                //adminul poate adauga sau poate sterge curse
                cout << "Alege o optiune: \n";
                cout << "1. Adauga curse\n2. Sterge curse \n";
                cout << "Introduceti o optiune: ";
                cin >> choice3;

                switch (choice3)
                {
                case 1:
                {
                    //adaugarea unei curse
                    cout << "Introduceti datele pentru noua cursa:\n";
                    string index, station, destination, date;

                    cout << "Index: ";
                    cin >> index;
                    cout << endl;

                    cout << "Statie de plecare: ";
                    cin >> station;
                    cout << endl;

                    cout << "Destinatie: ";
                    cin >> destination;
                    cout << endl;

                    cout << "Data (dd/mm/yyyy): ";
                    cin >> date;
                    cout << endl;

                    try
                    {
                        tripManager.addTripToFile(index, station, destination, date);
                        cout << "\nCursa adaugata cu succes!\n";
                    } // Capturarea și tratarea excepțiilor în caz de erori
                    catch (const DateInvalid& e)
                    {
                        cerr << "Eroare la adaugarea cursei: " << e.what() << endl;
                    }
                    catch (const CityInvalid& e)
                    {
                        cerr << "Eroare la adaugarea cursei: " << e.what() << endl;
                    }
                    catch(const CitySpecialCharacter& e)
                    {
                        cerr << "Eroare la adaugarea cursei: " << e.what() << endl;
                    }
                    catch(const DateInPast& e)
                    {
                        cerr <<"Eroare la adaugarea cursei: " << e.what() << endl;
                    }
                    break;
                }
                case 2:
                {
                    //stergerea unei curse
                    string indexToDelete;
                    cout << "Introduceti indexul cursei pe care doriti sa o stergeti: ";
                    cin >> indexToDelete;

                    tripManager.deleteTrip(indexToDelete);

                    break;
                }
                default:
                {
                    cout << "Optiune invalida\n";
                    break;
                }
                }
            }
            else
            {
                cout << "Nu ai drepturi de admin! \n";
            }
        }
    }
    else
    {
        cout << "Optiune invalida\n";
    }

    return 0;
}
