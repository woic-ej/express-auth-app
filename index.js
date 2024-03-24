const express = require("express");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");

const app = express();
const secretText = "superSecret";
const refreshSecretText = "supersuperSecret";

const posts = [
  {
    username: "John",
    title: "post1",
  },
  {
    username: "Han",
    title: "post2",
  },
];

let refreshTokens = [];

app.use(express.json());
app.use(cookieParser());

app.post("/login", (req, res) => {
  const username = req.body.username;
  const user = { name: username };

  //jwt를 이용해서 accessToken토큰 생성하기 payload + secretText
  const accessToken = jwt.sign(user, secretText, { expiresIn: "30s" });

  //jwt를 이용해서 refreshToken 토큰 생성하기 payload + secretText
  const refreshToken = jwt.sign(user, refreshSecretText, { expiresIn: "1d" });

  refreshTokens.push(refreshToken);

  //refreshToken을 쿠키에 넣어주기
  res.cookie("jwt", refreshToken, {
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000,
  });

  res.json({ accessToken });
});

const authMiddleware = (req, res, next) => {
  //토큰을 request headers에서 가져오기
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (token === null) return res.sendStatus(401);

  //유효한 토큰인지 확인
  jwt.verify(token, secretText, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

app.get("/posts", authMiddleware, (req, res) => {
  res.json(posts);
});

app.get("/refresh", (req, res) => {
  //cookie가져오기
  const cookies = req.cookies;
  if (!cookies?.jwt) return res.sendStatus(403);

  const refreshToken = cookies.jwt;
  //refreshToken이 DB에 있는지 확인
  if (!refreshTokens.includes(refreshToken)) {
    return res.sendStatus(403);
  }

  //토큰의 유효성 검사
  jwt.verify(refreshToken, refreshSecretText, (err, user) => {
    if (err) return res.sendStatus(403);

    //새로운 accessToken생성하기
    const accessToken = jwt.sign({ name: user.name }, secretText, {
      expiresIn: "30s",
    });

    res.send({ accessToken });
  });
});

const port = 4000;

app.listen(port, () => {
  console.log("listening on port " + port);
});
