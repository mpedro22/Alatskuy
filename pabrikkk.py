from datetime import datetime, timedelta
from typing import Annotated
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from pydantic import BaseModel
from typing import List
from jose import JWTError, jwt
import pyodbc
from httpx import AsyncClient
from fastapi.responses import JSONResponse
from typing import Optional
import requests


connection_string = 'Driver={ODBC Driver 18 for SQL Server};Server=tcp:mysqlserver8888.database.windows.net,1433;Database=myPabrikDB;Uid=azureuser;Pwd=Mp221003-;Encrypt=yes;TrustServerCertificate=no;Connection Timeout=30;Connection Login=60'


def create_connection():
    return pyodbc.connect(connection_string)


 
connection = create_connection()


# to get a string like this run:
# openssl rand -hex 32
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30000


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None = None


class UserLogin(BaseModel):
    username: str
    token: str
    isadmin: bool | None = None


class UserInDB(UserLogin):
    isadmin : bool
    hashedpassword: str
    token: Optional[str] = None
   
class RegisterData(BaseModel):
    username: str
    password : str
    nama : str
    alamat : str
    email : str
    notelp : str


class Alat(BaseModel):
    idalat : int
    namaalat : str
    kategori : str
    harga : int
    jumlah : int


class Pesanan(BaseModel):
    idpengguna : int
    idalat : int


class UpdatePesanan(BaseModel):
    idpesanan : int
    tanggalpesan : str
    statuspesan : str


class Pengguna(BaseModel):
    nama : str
    alamat : str
    email : str
    notelp : str
    katasandi : str


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


app = FastAPI()




def verify_password(plain_password, hashedpassword):
    return pwd_context.verify(plain_password, hashedpassword)




def get_password_hash(password):
    return pwd_context.hash(password)




def get_user(username: str):
    try:
        with connection.cursor() as cursor:
            cursor.execute(f"SELECT * FROM datalogin WHERE username = ?", username)
            row = cursor.fetchone()
        if row:
            user_dict = {
                "username": row.username,
                "hashedpassword": row.hashedpassword,
                "isadmin": row.isadmin,
                "token": row.token
            }
            return UserInDB(**user_dict)
        return None
    finally:
        # connection.close()
        print('done')




def authenticate_user(username: str, password: str):
    user = get_user(username)
    if not user:
        return False
    if not verify_password(password, user.hashedpassword):
        return False
    return user




def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt




async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


async def get_current_admin(
    current_user: Annotated[UserLogin, Depends(get_current_user)]
):
    if not current_user.isadmin:
        raise HTTPException(status_code=400, detail="Not Admin")
    return current_user


async def get_current_pelanggan(
    current_user: Annotated[UserLogin, Depends(get_current_user)]
):
    if current_user.isadmin:
        raise HTTPException(status_code=400, detail="Not Pelanggan")
    return current_user



@app.post("/register")
async def register_user_no_integration(data : RegisterData):
    cursor = connection.cursor()
    cursor.execute("SELECT 1 FROM datalogin WHERE username = ?", data.username)
    if cursor.fetchone():
        raise HTTPException(status_code=400, detail="Username already taken")


    # Hash the password before saving it to the database
    hashedpassword = pwd_context.hash(data.password)
    cursor.execute("SELECT COUNT(idlogin) FROM datalogin")
    count = int(cursor.fetchone()[0])


    # Insert the user data into the users_login table
    cursor.execute("""
        INSERT INTO datalogin (idlogin, username, hashedpassword, isadmin)
        VALUES (?, ?, ?, 0)
    """, count+1, data.username, hashedpassword)
   
    cursor.execute("SELECT COUNT(idpengguna) FROM pengguna")
    countUsers = int(cursor.fetchone()[0])


    cursor.execute("""
        INSERT INTO pengguna (idpengguna, nama, alamat, email, notelp, katasandi, username)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, countUsers+1, data.nama, data.alamat, data.email, data.notelp, hashedpassword, data.username)        
   


    # Commit the transaction
    connection.commit()
    return {"message": "User registered successfully"}

@app.post("/register/integration")
async def register_user_with_integration(data : RegisterData):
    cursor = connection.cursor()
    url = 'http://teachmeapi.dsc2b8fycmfsa5bp.eastus.azurecontainer.io/daftar/student'
    headers = {
        'accept': 'application/json',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    travis = {
           
            'nama': data.username,
            'password': data.password,
           
    }
    response = requests.post(url,headers=headers, params=travis)
    if response.status_code == 200:
        url = 'http://teachmeapi.dsc2b8fycmfsa5bp.eastus.azurecontainer.io/token'
        headers = {
            'accept': 'application/json',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        travis = {
                'grant_type': '',
                'username': data.username,
                'password': data.password,
                'scope': '',
                'client_id': '',
                'client_secret': ''
        }
        response = requests.post(url,headers=headers, data=travis)
        if response.status_code == 200:
            result = response.json()
            token = result.get('access_token')
    else:
        raise HTTPException(status_code=405, detail=response.text)
   
    cursor.execute("SELECT 1 FROM datalogin WHERE username = ?", data.username)
    if cursor.fetchone():
        raise HTTPException(status_code=400, detail="Username already taken")


    # Hash the password before saving it to the database
    hashedpassword = pwd_context.hash(data.password)
    cursor.execute("SELECT COUNT(idlogin) FROM datalogin")
    count = int(cursor.fetchone()[0])


    # Insert the user data into the users_login table
    cursor.execute("""
        INSERT INTO datalogin (idlogin, username, hashedpassword, isadmin, token)
        VALUES (?, ?, ?, 0,?)
    """, count+1, data.username, hashedpassword,token)
   
    cursor.execute("SELECT COUNT(idpengguna) FROM pengguna")
    countUsers = int(cursor.fetchone()[0])


    cursor.execute("""
        INSERT INTO pengguna (idpengguna, nama, alamat, email, notelp, katasandi, username)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, countUsers+1, data.nama, data.alamat, data.email, data.notelp, hashedpassword, data.username)        
   


    # Commit the transaction
    connection.commit()
    return {"message": "User registered successfully"}
   


@app.post("/token", response_model=Token)
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
   
    return {"access_token": access_token, "token_type": "bearer"}




@app.get("/details/me")
async def read_my_details(
    current_user: Annotated[UserLogin, Depends(get_current_user)]
):
    try:
        with connection.cursor() as cursor:
            if(current_user.username != 'admin'):
                cursor.execute("SELECT * FROM pengguna WHERE username=?", (current_user.username))
                user = cursor.fetchone()
                return {
                    'idpengguna': user[0],
                    'username' : user[6],
                    'nama' : user[1],
                    'alamat': user[2],
                    'email': user[3],
                    'no.telp' : user[4]
                }
            else:
                return{
                    'username' : 'admin',
                    'isadmin' : True
                }
    finally:
        # connection.close()
        print('done')




@app.get('/pengguna')
async def read_all_user(
    current_user: Annotated[UserLogin, Depends(get_current_admin)]
):
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM pengguna")
            users = cursor.fetchall()


        user_list = []
        for user in users:
            user_dict = {
                    'idpengguna': user[0],
                    'username' : user[6],
                    'nama' : user[1],
                    'alamat': user[2],
                    'email': user[3],
                    'no.telp' : user[4]
            }
            user_list.append(user_dict)


        return user_list
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal Server Error: {str(e)}")
    finally:
        # Optionally close the connection here if needed
        # connection.close()
        print('done')




@app.get('/alat')
async def read_all_alat(
):
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM alat")
            alats = cursor.fetchall()


        listAlat = []
        for alat in alats:
            alat_dict = {
                    'idalat': alat[0],
                    'namaalat' : alat[1],
                    'kategori' : alat[2],
                    'harga': alat[3],
                    'jumlah': alat[4]
            }
            listAlat.append(alat_dict)


        return listAlat
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal Server Error: {str(e)}")
    finally:
        # Optionally close the connection here if needed
        # connection.close()
        print('done')


@app.get('/pesanan')
async def read_all_pesanan(
    current_user: Annotated[UserLogin, Depends(get_current_admin)]
):
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM pesanan")
            pesanans = cursor.fetchall()


        listPesanan = []
        for pesanan in pesanans:
            pesanan = {
                    'idpesanan': pesanan[0],
                    'idpengguna' : pesanan[1],
                    'idalat' : pesanan[2],
                    'tanggalpesanan': pesanan[3],
                    'statuspesan': pesanan[4]
            }
            listPesanan.append(pesanan)


        return listPesanan
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal Server Error: {str(e)}")
    finally:
        # Optionally close the connection here if needed
        # connection.close()
        print('done')






   


@app.post('/alat')
async def add_alat(
    current_user: Annotated[UserLogin, Depends(get_current_admin)],
    data : Alat
):
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1 FROM alat WHERE idalat = ?", data.idalat)
            if cursor.fetchone():
                raise HTTPException(status_code=400, detail="idalat already taken")


            # Insert the user data into the users_login table
            cursor.execute("""
                INSERT INTO alat (idalat, namaalat, kategori, harga, jumlah)
                VALUES (?, ?, ?, ?, ?)
            """, data.idalat, data.namaalat, data.kategori, data.harga, data.jumlah)
               


            # Commit the transaction
            connection.commit()
            return {"message": "Alat registered successfully"}
    finally:
        # connection.close()
        print('done')






@app.put('/update/me')
async def update_my_data(
    current_user: Annotated[UserLogin, Depends(get_current_pelanggan)],
    data : Pengguna
):
    try:
        with connection.cursor() as cursor:
            cursor.execute("UPDATE pengguna SET nama=?, alamat=?, email=?, notelp=?, katasandi=? WHERE username=?",
                           (data.nama, data.alamat, data.email, data.notelp, get_password_hash(data.katasandi), current_user.username))
           
            cursor.execute("UPDATE datalogin SET hashedpassword=? WHERE username=?",
                           (get_password_hash(data.katasandi), current_user.username))


            # Commit the transaction
            connection.commit()
            return {"message": "Users updated successfully"}
    finally:
        # connection.close()
        print('done')




@app.put('/update/me')
async def update_my_data(
    current_user: Annotated[UserLogin, Depends(get_current_pelanggan)],
    data : Pengguna
):
    try:
        with connection.cursor() as cursor:
            cursor.execute("UPDATE pengguna SET nama=?, alamat=?, email=?, notelp=?, katasandi=? WHERE username=?",
                           (data.nama, data.alamat, data.email, data.notelp, get_password_hash(data.katasandi), current_user.username))
           
            cursor.execute("UPDATE datalogin SET hashedpassword=? WHERE username=?",
                           (get_password_hash(data.katasandi), current_user.username))


            # Commit the transaction
            connection.commit()
            return {"message": "Users updated successfully"}
    finally:
        # connection.close()
        print('done')


@app.put('/alat')
async def update_alat(
    current_user: Annotated[UserLogin, Depends(get_current_admin)],
    data : Alat
):
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1 FROM alat WHERE idalat = ?", data.idalat)
            if not cursor.fetchone():
                raise HTTPException(status_code=400, detail=f"no alat with id = {data.idalat}")


            cursor.execute("UPDATE alat SET namaalat=?, kategori=?, harga=?, jumlah=? WHERE idalat=?",
                           (data.namaalat, data.kategori, data.harga, data.jumlah, data.idalat))


            # Commit the transaction
            connection.commit()
            return {"message": "Alat updated successfully"}
    finally:
        # connection.close()
        print('done')




@app.delete('/pengguna/{idpengguna}')
async def delete_sneaker(current_user: Annotated[UserLogin, Depends(get_current_admin)], idpengguna: int):
    try:
        with connection.cursor() as cursor:


            cursor.execute("SELECT username FROM pengguna WHERE idpengguna=?", (idpengguna))
            pengguna = cursor.fetchone()


            username = pengguna[0]


            if not pengguna:
                raise HTTPException(
                    status_code=404, detail=f'Pengguna with ID {idpengguna} not found.'
                )


            cursor.execute("DELETE FROM pengguna WHERE idpengguna=?", (idpengguna))
            cursor.execute("DELETE FROM datalogin WHERE username=?", (username))


            connection.commit()


            return "Pengguna deleted"


    finally:
        # connection.close()
        print('done')


@app.get('/rekomendasi')
async def rekomendasi(
    current_user: Annotated[UserLogin, Depends(get_current_user)],
    bidang : str
):
        user=get_user(current_user.username)
        cursor=connection.cursor()
        url = 'http://teachmeapi.dsc2b8fycmfsa5bp.eastus.azurecontainer.io/rekomendasi/tutor'
        headers = {
            'accept': 'application/json',
            'Authorization': 'bearer ' + user.token,
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        params = {'topik': bidang}


        async with AsyncClient() as client:
            response = await client.get(url, headers=headers, params=params)


        if response.status_code == 200:
            data = response.json()
            cursor.execute("select * from alat where kategori = '%s'"%(bidang))
            rows=[]
            for row in cursor.fetchall():
                rows.append({"nama alat":row.namaalat, "harga":row.harga})
            return data + rows
        
@app.get('/rekomendasi/alat')
async def rekomendasi_alat(
    current_user: Annotated[UserLogin, Depends(get_current_user)],
    bidang : str
):
        user=get_user(current_user.username)
        cursor=connection.cursor()
        cursor.execute("select * from alat where kategori = '%s'"%(bidang))
        rows=[]
        for row in cursor.fetchall():
            rows.append({"nama alat":row.namaalat, "harga":row.harga})
        return rows
   


@app.post('/makeappointment')
async def appointment(
    current_user: Annotated[UserLogin, Depends(get_current_user)],
    teacherID : int,
    tanggal:str
):
        user=get_user(current_user.username)
        url = 'http://teachmeapi.dsc2b8fycmfsa5bp.eastus.azurecontainer.io/makeappointment'
        headers = {
            'accept': 'application/json',
            'Authorization': 'bearer ' + user.token,
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        params = {'teacherID': teacherID, 'tanggal':tanggal}


        response =  requests.post(url, headers=headers, params=params)


       


        if response.status_code == 200:
            data = response.json()
            return data