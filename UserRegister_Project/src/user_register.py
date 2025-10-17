from typing import Dict, List


class UserRegister:
    def __init__(self, input_files: List[str]):
        self._users = {}
        self._load_files(input_files)
    
    # 1. Sladja
    # def _load_files(self, input_files: List[str]):
    # Metoda prima listu stringova (putanja) do ulaznih fajlova
    # Iterira kroz sve ulazne fajlove
    # Za svaki fajl, otvara ga i učitava JSON podatke json.load(file)
    # Poziva metodu _process_users za obradu korisnika iz učitanih podataka
    # Obrada grešaka prilikom učitavanja fajlova (pomocu izuzetaka)
    
    def _process_users(self, data: List[Dict], file_path: str):
        for user in data:
            try:
                # Extract user information
                name = user.get('name', '')
                email = user.get('email', '')
                ip = user.get('ip', '')
                devices = user.get('devices', [])
                
                # Validate email and IPv4
                if not self._is_valid_email(email):
                    print(f"Invalid email format: {email} in file {file_path}")
                    continue
                
                if not self._is_valid_ipv4(ip):
                    print(f"Invalid IPv4 format: {ip} for user {email} in file {file_path}")
                    continue
                
                # Add or update user
                if email in self._users:
                    # User exists, merge devices
                    existing_devices = set(self._users[email]['devices'])
                    new_devices = set(devices)
                    merged_devices = list(existing_devices.union(new_devices))
                    
                    self._users[email]['devices'] = merged_devices
                    print(f"Merged devices for duplicate user: {email}")
                else:
                    # New user
                    self._users[email] = {
                        'name': name,
                        'ip': ip,
                        'devices': devices
                    }
            except Exception as e:
                print(f"Error processing user in file {file_path}: {str(e)}")

    # 1. Sladja
    def _is_valid_email(email: str) -> bool:
        # Provjerava da li je uneseni email validan
        # Definise se odgovarajuci pattern
        # Vraća True ako je email validan, False inače
    
    # 1. Sladja
    def _is_valid_ipv4(ip: str) -> bool:
        # Provjerava da li je unesena IPv4 adresa validna
        # Isto se definise pattern, vraca true ako jeste u suprotnom false

    def __getitem__(self, email: str) -> Dict:
        if email not in self._users:
            raise KeyError(f"User with email {email} not found in the register")
        return self._users[email].copy()
    
    def __setitem__(self, email: str, user_data: Dict):
        required_keys = {'name', 'ip', 'devices'}
        if not required_keys.issubset(set(user_data.keys())):
            raise ValueError(f"User data must contain: {', '.join(required_keys)}")

        if not self._is_valid_ipv4(user_data['ip']):
            raise ValueError(f"Invalid IPv4 format: {user_data['ip']}")
        
        self._users[email] = user_data.copy()
    
    def get_devices(self, email: str) -> List[str]:
        return self[email]['devices'].copy()

    def set_devices(self, email: str, devices: List[str]):
        if email not in self._users:
            raise KeyError(f"User with email {email} not found in the register")
        self._users[email]['devices'] = devices.copy()

    def set_name(self, email: str, name: str):
        if email not in self._users:
            raise KeyError(f"User with email {email} not found in the register")
        self._users[email]['name'] = name

    def get_name(self, email: str) -> str:
        return self[email]['name']

    def set_ip(self, email: str, ip: str):
        if email not in self._users:
            raise KeyError(f"User with email {email} not found in the register")
        
        if not self._is_valid_ipv4(ip):
            raise ValueError(f"Invalid IPv4 format: {ip}")

        self._users[email]['ip'] = ip

    def get_ip(self, email: str) -> str:
        return self[email]['ip']
    
    # 3. Uros
    def __add__(self, other: 'UserRegister') -> 'UserRegister':
    # Metoda za dodavanje novog registra korisnika, radi se unija, vraca se novi registar

    # 3. Uros
    def __mul__(self, other: 'UserRegister') -> 'UserRegister':
    # Metoda za mnozenje dva registra korisnika, radi se presjek, vraca se novi registar

    # 3. Uros
    def print_register(self):
    # Metoda za ispis sadrzaja registra na standardni izlaz u odredjenom formatu

    # 3. Uros
    def __len__(self) -> int:
    # Preklopljena metoda za dobijanje broja korisnika u registru