
import re
import bcrypt

class Manejo_Usuarios:

    # metodo constructor de la clase
    def __init__(self,):
        self._usuarios_y_contrasenas = []
        self.codigo = bcrypt.gensalt()
        print("Objeto instanciado...")


    # metodo para validad usuario y contraseña
    def validar_usuario_y_contrasena(self, usuario : str, contrasena : str) -> dict:
        
        # SANITIZANDO el nombre de usuario
        # eliminando la ñ y el punto del usuario
        usuario_modificado = re.sub(r'[ñ.]',"",usuario)
        if (usuario != usuario_modificado):
            print("Se eliminaron caracters indeseados de su usuario y quedo como: %s .", usuario_modificado)
        else: 
            print("Su usuario tiene un formato válido.")


        # VALIDAR contraseña
        if (len(contrasena)<10):
            raise ValueError("La contraseña debe de tener almenos 10 caractéres")
        
        # Validar que tenga una mayúscula
        if not re.search(r'[A-Z]', contrasena):
            raise ValueError("La contraseña debe de tener una letra mayúscula")
        
        # Validar que tenga una minuscula
        if not re.search(r'[a-z]', contrasena):
            raise ValueError("La contraseña debe de tener una letra minuscula")
        
        # Validar que tenga un número
        if not re.search(r'[0-9]', contrasena):
            raise ValueError("La contraseña debe de tener un número")
        
        # Validar que tenga un caracter especial
        if not re.search(r'[!#$*@]', contrasena):
            raise ValueError("La contraseña debe de tener un carácter especial de estos ! # $ * @")
        
        contrasena = self._incriptar_contraseña(contrasena)

        temp_user_pw = {"usuario":usuario_modificado,"contrasena":contrasena}
        self._usuarios_y_contrasenas.append(temp_user_pw)
        return temp_user_pw
    

    def _incriptar_contraseña(self, contrasena_validada : str) -> bytes:
        try:
            encriptada_contrasena = bcrypt.hashpw(contrasena_validada.encode("utf-8"),self.codigo)
            return encriptada_contrasena
        except ValueError as error:
            print(f"El proceso de encriptado de la contraseña falló {error}")

    def mostrar_base_de_datos(self,):
        for elemento in self._usuarios_y_contrasenas:
            for key in elemento.keys():
                print(f"{key}: {elemento[key]}")

def main():
    almacen_de_usuarios =  Manejo_Usuarios()

    almacen_de_usuarios.validar_usuario_y_contrasena("Rscd27","Ab1!valida")
    almacen_de_usuarios.validar_usuario_y_contrasena("Johnñ2","Ab1!valida")
    almacen_de_usuarios.validar_usuario_y_contrasena("Ryan15","Ab1!valida")

    almacen_de_usuarios.mostrar_base_de_datos()

if __name__ == '__main__':
    main()
