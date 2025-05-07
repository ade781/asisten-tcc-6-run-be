import User from "../models/UserModel.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

// GET
async function getUsers(req, res) {
  try {
    const users = await User.findAll();
    res.status(200).json({
      status: "Success",
      message: "Users Retrieved",
      data: users,
    });
  } catch (error) {
    res.status(error.statusCode || 500).json({
      status: "Error",
      message: error.message,
    });
  }
}

// GET BY ID
async function getUserById(req, res) {
  try {
    const user = await User.findOne({ where: { id: req.params.id } });
    if (!user) {
      const error = new Error("User tidak ditemukan 😮");
      error.statusCode = 400;
      throw error;
    }
    res.status(200).json({
      status: "Success",
      message: "User Retrieved",
      data: user,
    });
  } catch (error) {
    res.status(error.statusCode || 500).json({
      status: "Error",
      message: error.message,
    });
  }
}

// CREATE
async function createUser(req, res) {
  try {
    const { name, email, gender, password } = req.body;
    if (!name || !email || !gender || !password) {
      const msg = `${!name ? "Name" : !email ? "Email" : "Gender"
        } field cannot be empty 😠`;
      const error = new Error(msg);
      error.statusCode = 401;
      throw error;
    }

    const encryptPassword = await bcrypt.hash(password, 5);

    await User.create({
      name: name,
      email: email,
      gender: gender,
      password: password
    });
    res.status(201).json({
      status: "Success",
      message: "User Created",
    });
  } catch (error) {
    res.status(error.statusCode || 500).json({
      status: "Error",
      message: error.message,
    });
  }
}

async function updateUser(req, res) {
  try {
    const { name, email, gender, password } = req.body;
    const ifUserExist = await User.findOne({ where: { id: req.params.id } });

    if (!name || !email || !gender || !password) {
      const msg = `field cannot be empty 😠`;
      const error = new Error(msg);
      error.statusCode = 401;
      throw error;
    }
    const encryptPassword = await bcrypt.hash(password, 5);
    const updatedData = {
      name: name,
      email: email,
      gender: gender,
      password: password
    }

    if (!ifUserExist) {
      const error = new Error("User tidak ditemukan 😮");
      error.statusCode = 400;
      throw error;
    }

    await User.update(req.body, {
      where: { id: req.params.id },
    });

    res.status(200).json({
      status: "Success",
      message: "User Updated",
    });
  } catch (error) {
    res.status(error.statusCode || 500).json({
      status: "Error",
      message: error.message,
    });
  }
}

async function deleteUser(req, res) {
  try {
    const ifUserExist = await User.findOne({ where: { id: req.params.id } });
    if (!ifUserExist) {
      const error = new Error("User tidak ditemukan 😮");
      error.statusCode = 400;
      throw error;
    }

    await User.destroy({ where: { id: req.params.id } });
    res.status(200).json({
      status: "Success",
      message: "User Deleted",
    });
  } catch (error) {
    res.status(error.statusCode || 500).json({
      status: "Error",
      message: error.message,
    });
  }
}

async function loginHandler(req, res) {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({
      where: {
        email: email
      }
    });

    if (user) {
      //Data User itu nanti bakalan dipake buat ngesign token kan
      // data user dari sequelize itu harus diubah dulu ke bentuk object
      //Safeuserdata dipake biar lebih dinamis, jadi dia masukin semua data user kecuali data-data sensitifnya  karena bisa didecode kayak password caranya gini :
      const userPlain = user.toJSON(); // Konversi ke object
      const { password: _, refresh_token: __, ...safeUserData } = userPlain;


      const decryptPassword = await bcrypt.compare(password, user.password);
      if (decryptPassword) {
        const accessToken = jwt.sign(safeUserData, process.env.ACCESS_TOKEN_SECRET, {
          expiresIn: '30s'
        });
        const refreshToken = jwt.sign(safeUserData, process.env.REFRESH_TOKEN_SECRET, {
          expiresIn: '1d'
        });
        await User.update({ refresh_token: refreshToken }, {
          where: {
            id: user.id
          }
        });
        res.cookie('refreshToken', refreshToken, {
          httpOnly: false, //ngatur cross-site scripting, untuk penggunaan asli aktifkan karena bisa nyegah serangan fetch data dari website "document.cookies"
          sameSite: 'none',  //ini ngatur domain yg request misal kalo strict cuman bisa akseske link dari dan menuju domain yg sama, lax itu bisa dari domain lain tapi cuman bisa get
          maxAge: 24 * 60 * 60 * 1000,
          secure: true //ini ngirim cookies cuman bisa dari https, kenapa? nyegah skema MITM di jaringan publik, tapi pas development di false in aja
        });
        res.status(200).json({
          status: "Succes",
          message: "Login Berhasil",
          safeUserData,
          accessToken
        });
      }
      else {
        res.status(400).json({
          status: "Failed",
          message: "Paassword atau email salah",

        });
      }
    } else {
      res.status(400).json({
        status: "Failed",
        message: "Paassword atau email salah",
      });
    }
  } catch (error) {
    res.status(error.statusCode || 500).json({
      status: "error",
      message: error.message
    })
  }
}

//nambah logout
async function logout(req, res) {
  const refreshToken = req.cookies.refreshToken; //mgecek refresh token sama gak sama di database
  if (!refreshToken) return res.sendStatus(204);
  const user = await User.findOne({
    where: {
      refresh_token: refreshToken
    }
  });
  if (!user.refresh_token) return res.sendStatus(204);
  const userId = user.id;
  await User.update({ refresh_token: null }, {
    where: {
      id: userId
    }
  });
  res.clearCookie('refreshToken'); //ngehapus cookies yg tersimpan
  return res.sendStatus(200);
}

export { getUsers, getUserById, createUser, updateUser, deleteUser, loginHandler, logout };