const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const gravatar = require("gravatar");
const path = require("path");
const fs = require("fs/promises");
const { nanoid } = require("nanoid");

const { User } = require("../models/user");

const { HttpError, ctrlWrapper, resize, sendEmail } = require("../helpers");

const { SECRET_KEY, BASE_URL } = process.env;

const avatarsDir = path.join(__dirname, "../", "public", "avatars");

const register = async (req, res) => {
  const { email, password } = req.body; // берем email и пароль из req.body
  const user = await User.findOne({ email }); // делаем запрос есть ли в базе такой email
  if (user) {
    throw HttpError(409, "Email in use");
  }
  
  const hashPassword = await bcrypt.hash(password, 10); // хешируем пароль
  const avatarURL = gravatar.url(email);

  const verificationToken = nanoid();

  const newUser = await User.create({...req.body, password: hashPassword, avatarURL, verificationToken}); // сохраняем пользователя в базе

  const verifyEmail = {
    to: email,
    subject: "Verify email",
    html: `<a target="_blank" href="${BASE_URL}/users/verify/${verificationToken}">Click verify email</a>`,
  };
  await sendEmail(verifyEmail);

  res.status(201).json({
    user: {
      email: newUser.email,
    subscription: newUser.subscription,
    },    
  });
};

const verifyEmail = async(req, res) => {
  const { verificationToken } = req.params;
  const user = await User.findOne({ verificationToken });
  if(!user){
    throw HttpError(401, "User not found");
  }
  await User.findByIdAndUpdate(user._id, { verify: true, verificationToken: "" });

  res.json({
    message: "Verification successful",
  });
};

const resendVerifyEmail = async (req, res) => {
  const { email } = req.body;
  const user = await User.findOne({ email });
  if (!user) {
    throw HttpError(401, "Email not found");
  }
   if (user) {
     throw HttpError(401, "Email already verify");
  }
  const verifyEmail = {
    to: email,
    subject: "Verify email",
    html: `<a target="_blank" href="${BASE_URL}/users/verify/${user.verificationToken}">Click verify email</a>`,
  };
  await sendEmail(verifyEmail);

  res.json({
    message: "Verify email send success"
  })

}

const login = async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email }); // проверяем наличие пользователя в базе
  if (!user) {
    throw HttpError(401, "Email or password is wrong");
  }  // если пользователь есть - сравниваем пароли

  // другий крок - верифікація email
  if (!user.verify) {
    throw HttpError(401, "Email not verified");
  }
  const passwordCompare = await bcrypt.compare(password, user.password);
  if (!passwordCompare) {
    throw HttpError(401, "Email or password is wrong");
  }

  const payload = {
    id: user._id,
  }
  const token = jwt.sign(payload, SECRET_KEY, { expiresIn: "23h" }); // шифруем token секретным ключом
  await User.findByIdAndUpdate(user.id, { token });

  res.json({
    token,
    user: {
      email: user.email,
      subscription: user.subscription,
    },
  });
};

const getCurrent = async (req, res) => {
  const { email, subscription } = req.user;
   
  res.json({
    email,
    subscription,
  })
};

const logout = async (req, res) => {
  const {_id } = req.user;
  await User.findByIdAndUpdate(_id, { token: "" });

  res.status(204).json({})
}

const updateAvatar = async (req, res) => {
  const { _id } = req.user;
  const { path: tmpUpload, originalname } = req.file;
  await resize(tmpUpload); // оброблюємо зображення
  const filename = `${_id}_${originalname}`;  // додаємо id до імені файлу щоб зробити його унікальним
  const resultUpload = path.join(avatarsDir, filename);
  await fs.rename(tmpUpload, resultUpload); // переміщуємо файл з тимчасової папки tmp в publik/avatars
  const avatarURL = path.join("avatars", filename);   // шлях записуємо в базу
  await User.findByIdAndUpdate(_id, { avatarURL });  // знаючи id перезаписуємо avatarURL

  res.json({
    avatarURL,
  })
}

module.exports = {
  register: ctrlWrapper(register),
  verifyEmail: ctrlWrapper(verifyEmail),
  resendVerifyEmail: ctrlWrapper(resendVerifyEmail),
  login: ctrlWrapper(login),
  getCurrent: ctrlWrapper(getCurrent),
  logout: ctrlWrapper(logout),
  updateAvatar: ctrlWrapper(updateAvatar),
};
