from optparse import Option
import bcrypt
from fastapi import Depends, FastAPI, HTTPException, status, APIRouter
from pydantic import BaseModel
from typing import Optional
from . import modelsMKT
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from .databaseMKT import SessionLocal, engine
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from jose import jwt, JWTError
from datetime import datetime, timedelta

SECRET_KEY = "qazwsxabmmkt"
# Adhiere mayor seguridad al token y es la firma que lo acomapaña
ALGORITHMA = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 20

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class Create_user(BaseModel):
    usr_login : str
    usr_alias : str
    usr_password : str
    usr_enabled : bool 
    usr_creation_date : datetime
    usr_auth_reaim : str 

bcrypt_context = CryptContext(schemes= ["bcrypt"], deprecated = "auto" )

# La siguiente linea creara la base de datos y la tabla con todo lo necesario en caso
# de por alguna razon se ejecute auth.py antes que main.py

modelsMKT.Base.metadata.create_all(bind=engine)

# El Bearer es un portador del token
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="http://127.0.0.1:9000/auth/token")
# Creamos la variable usando la clase que importamos y pasamos el tokenUrl
# que contiene el token generado cuando el usuario inicia sesion

app = FastAPI()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_password_hash(password):
    return bcrypt_context.hash(password)
# Crea el encrypted hash password

def verify_password(plain_password, hash_password):
    return bcrypt_context.verify(plain_password, hash_password)

# .verify compara si la contraseña ingresada por el usuario al intentar el sign in 
# coincido con la hash password guardad en la db

def authenticate_user(username : str, password : str, db: Session = Depends(get_db)):
    user = db.query(modelsMKT.Users).filter(modelsMKT.Users.usr_login == username).first()
    if not user:
        return False
    # En la siguiente instruccion le decimos que si no esta verificada la 
    # contraseña, que devuelva Falso para indicar que el usuario no es autentificado
    if not verify_password(password, user.usr_password):
        # La funcion comparo si la password que ingreso el usuario coincide con la guardada en la db (user proviene de models)
        return False
    return user

# Cada vez que un usuario inicia sesion se crea un token distinto, o el mismo puede expirar en un cierto tiempo
# El token se crea cuando se inicia sesion
def create_access_token(username: str, expire_time : Optional[timedelta] = None):
    # Creamos la sentencia que se va incluir en el token con los datos
    encode = {"user": username} 
    # Generamos un tiempo de expiracion, asi el usuario no se matiene logueado 
    # si no que a determinado tiempo se cierra la sesion
    if expire_time:
        # lo hago para verificar que el tiempo no haya expirado ya
        expire = datetime.utcnow() + expire_time
    else: 
        expire = datetime.utcnow() + timedelta(minutes=15)
    # Actualizamos los datos del usuarios con el tiempo de expiracion
    encode.update({"exp": expire})
    # finalmente devolvemos el JWT, codificamos con jwt los datos codificados, la security key y el algorithm  
    return jwt.encode(encode, SECRET_KEY, algorithm=ALGORITHMA) # codifica 

# Con esta funcion vamos a decodificar el JWT para obtener el usuario solo
# luego de obtener el usuario , vamos a poder validar que usuario esta dentro del JWT 
# El get current user solo funciona cuando el usuario ya fue validado (es decir pudo iniciar sesion ya que existe su cuenta)
# Finalmente esta funcion devolvera el usuario
async def get_current_user(token: str = Depends(oauth2_scheme), db : Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHMA]) # decodifica
        # Con decirle el .decode estamos diciendole que payload sera el token, la secret key y el alg decodificado
        username: str = payload.get("user")
        # con el payload.get estamos buscando en USER que habiamos definido antes, que era el username del cliente
        if username is None:
            raise get_user_exception
        token_data = TokenData(username=username)
        # SI existen quiero devolver un diccionario que indique el username
    except JWTError: 
        # Uso el JWTError para indicar que no encontre un usuario valido dentro del JWT
        raise get_user_exception
    user = db.query(modelsMKT.Users).filter(modelsMKT.Users.usr_login == token_data.username).first()
    if user is None:
        raise get_user_exception
    return user

# Creamos get current active user para obtener el usuario solo si esta activo
# Entonces, en nuestro punto final, solo obtendremos un usuario si el usuario existe, 
# se autenticó correctamente y está activo:
async def get_current_active_user(current_user: Create_user = Depends(get_current_user)):
    if not current_user.usr_enabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

"""def read_user_me_utility(current_user: Create_user = Depends(get_current_active_user)):
    if not current_user:
        raise get_user_exception()"""

def token_auth2(token: str = Depends(oauth2_scheme), current_user: Create_user = Depends(get_current_active_user)):
    if not current_user:
        raise get_user_exception()
    elif not token:
        raise token_exception()




@app.post("/create/user")
async def create_new_user(createuser : Create_user, db: Session = Depends(get_db)):
    create_user_Model = modelsMKT.Users()
    create_user_Model.usr_login = createuser.usr_login
    create_user_Model.usr_alias = createuser.usr_alias
    hash_password = get_password_hash(createuser.usr_password)
    create_user_Model.usr_password = hash_password
    create_user_Model.usr_enabled = createuser.usr_enabled
    create_user_Model.usr_creation_date = createuser.usr_creation_date
    create_user_Model.usr_auth_reaim = createuser.usr_auth_reaim

    db.add(create_user_Model)
    db.commit()

@app.post("/auth/token")
async def login_for_acces_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session= Depends(get_db)):
    user = authenticate_user(form_data.username, form_data.password, db)
    if not user:
        raise token_exception
    token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(user.usr_login, expire_time=token_expires)
    return {"access_token": access_token, "token_type": "bearer"}
    # Devuelve un token de acceso real
    # Este "token" es el que pertenece al Outh2Barer

    # El token lo que genera es que el usuario sea reconocido


    #la funcion authenticate me devuelve el usuario ya validado, por lo que en esta funcion 
    # utilizo ese mismo usuario y creo el token de acceso con el form_data(la forma que va a tener la informacion del usuarrio, 
    # # que es la que nos otorga el OAuthForm)
    # OAuth2PasswordRequestFormtiene atributos de uso común como 'nombre de usuario', 'contraseña' y 'alcance'.
    # Después de verificar en la base de datos que el usuario existe, se crea un token de acceso para el usuario. 
    # El token de acceso consta de datos que describen al usuario, sus límites de tiempo de acceso y los permisos 
    # de alcance que se le asignan y que se codifica en un objeto compacto de tipo cadena, que es el token.

# Inyectar el usuario actual 
# Usamos el get current user en nuestra ruta get user 
@app.get("/users/me", response_model= Create_user)
async def read_user_me(current_user: Create_user = Depends(get_current_active_user)):
    return current_user
# Sirve para ver los datos del usuario que se registro
# Tenga en cuenta que declaramos el tipo de current_user como el modelo Pydantic User.
# Ahora puede obtener al usuario actual directamente en las funciones de operación de ruta 
# Es decir desde el swagger de fastapi


#Exceptions 
def get_user_exception():
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    return credentials_exception


def token_exception():
    token_exception_response = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Incorrect username or password",
        headers={"WWW-Authenticate": "Bearer"},
    )
    return token_exception_response