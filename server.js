const path = require('path')
const fs = require('fs') // node裡的文件讀取系統
const jsonServer = require('json-server')
const jwt = require('jsonwebtoken')
const server = jsonServer.create()
const router = jsonServer.router(path.join(__dirname, 'db.json')) //使用絕對路徑
const middlewares = jsonServer.defaults()
server.use(jsonServer.bodyParser) // 使用解析器
server.use(middlewares)

// 解析資料
const getUserDB = () =>{
  return JSON.parse(
      fs.readFileSync(path.join(__dirname,'users.json'),'utf-8')
    )
  // 獲取文件絕對路徑 使用utf-8編碼 轉成json
}
const isAuthenticated = ({ email, password}) => {
  // 返回index 如果存在會 >-1 否則 = -1
  return getUserDB().users.findIndex(user => user.email === email && user.password === password) !== -1
}
// 有可能信箱相同 密碼不同還是會給過
const isExist = (email) => {
  // 返回index 如果存在會 >-1 否則 = -1
  return getUserDB().users.findIndex(user => user.email === email) !== -1
}

const SECRET ="sd47hjhe5d4s5d4s5d4s5ds8retrdf5" // 簽名的密鑰
const expiresIn="1h" //有效時間
// 定義註冊函數  payload是伺服器端希望最終返回客戶端的數據
const createToken = payload => {
  return jwt.sign(payload, SECRET, { expiresIn })
}


// 自定義接口 加入nodemon 改指令 node -> nodemon可以實時監聽js並重啟
server.post('/auth/login',(req, res)=>{
  const { email, password} = req.body;
  if(isAuthenticated({ email, password})){
    // 找使用者數據
    const user =  getUserDB().users.find(
      u => u.email === email && u.password === password
    );
    // 拿到想用的數據
    const{ nickname, type} = user;
    //JWT
    const jwtToken = createToken({ email, nickname, type});
    return res.status(200).json(jwtToken);
  }else{
    const status = 401;
    const message = 'Incorrect email or password';
    return res.status(status).json(status,message)
  }
})

// 註冊邏輯
server.post('/auth/register',(req,res)=>{
  const { email, password, nickname, type} =req.body;
  // Step 1 假如重複報錯
  if(isExist(email)){
    const status = 401;
    const message = 'Email and password already exist'
    return res.status(status).json({status, message})
  }
  // Step 2 讀取json
  fs.readFile(path.join(__dirname, 'users.json'),(err, _data)=>{
    if(err){
      const status = 401;
      const message = err;
      return res.status(status).json({status, message})
    }
    // Get Current Users Data
    const data = JSON.parse(_data.toString());
    // Get the ID of last user
    const last_item_id = data.users[data.users.length - 1].id;
    // Add New User
    data.users.push({id: last_item_id + 1, email, password, nickname, type});
    fs.writeFile(
      path.join(__dirname,'users.json'),
      JSON.stringify(data),
      (err, result)=>{
        //Write
        if(err){
          const status = 401;
          const message = err;
          res.status(status).json({status, message});
          return
        }
      }
    )
  })
  const jwToken = createToken({nickname, type, email});
  res.status(200).json(jwToken);
});

// 控制接口 購物車api請求
// 傳多個 ['/carts','/products'] 匹配條件 /^(?!\/auth).*$/
server.use('/carts',(req, res, next) =>{
  // 拿到http請求字段 客戶端請求 放在http請求的頭部訊息 Authorization: Bearer<token>
  if(
    req.headers.authorization === undefined ||
    req.headers.authorization.split(' ')[0] !== 'Bearer'
  ){
    const status = 401;
    const message = 'Error in authorization format';
    res.status(status).json({ status, message});
    return;
  }
  try {
    const verifyTokenResult = verifyToken(
      req.headers.authorization.split(' ')[1]
    );
    if(verifyTokenResult instanceof Error){
      const status = 401;
      const message = 'Access token not provided';
      res.status(status).json({ status, message});
      return
    }
    next(); // next調用後會繼續處裡原始/carts的請求
  } catch (error) {
    const status = 401;
    const message = 'Error token is revoked';
    res.status(status).json({ status, message});
  }
});

// 驗證Token
const verifyToken = token =>{
  return jwt.verify(token, SECRET, (err, decode)=>
    decode !== undefined ? decode : err
  )
}

server.use(router)
server.listen(3004, () => {
  console.log('JSON Server is running')
})
