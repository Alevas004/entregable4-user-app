const User = require("../modals/User");
const catchError = require("../utils/catchError");
const bcrypt = require("bcrypt");
const sendEmail = require("../utils/sendEmail");
const EmailCode = require("../modals/EmailCode");
const jwt = require('jsonwebtoken');


const getAll = catchError(async (req, res) => {
  const users = await User.findAll();
  return res.json(users);
});

const create = catchError(async (req, res) => {
  const { email, password, firstName, lastName, country, image, frontBaseUrl } =
    req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  const user = await User.create({
    email,
    password: hashedPassword,
    firstName,
    lastName,
    country,
    image,
  });
  const code = require("crypto").randomBytes(32).toString("hex");
  const link = `${frontBaseUrl}/auth/verify_email/${code}`;

  await EmailCode.create({
    code,
    userId: user.id,
  });

  await sendEmail({
    to: email,
    subject: "Verificate email for user app",
    html: `
      <h2> Hello ${firstName} ${lastName}</h2>
      <p>Verify your account clicking this link</p>
      <a href="${link}" >${link}</a>
      <h4>Thanks for signing up in user app</h4>
    `,
  });

  return res.status(201).json(user);
});

const getOne = catchError(async (req, res) => {
  const { id } = req.params;
  const user = await User.findByPk(id);
  if (!user) return res.sendStatus(401);
  return res.json(user);
});

const remove = catchError(async (req, res) => {
  const { id } = req.params;
  await User.destroy({ where: { id } });
  return res.sendStatus(401);
});

const update = catchError(async (req, res) => {
  const { id } = req.params;
  const { firstName, lastName, country, image } = req.body;
  const user = User.update(
    { firstName, lastName, country, image },
    { where: { id }, returning: true }
  );
  if (!user) return res.sendStatus(404);
  return res.json(user);
});

const verifyCode = catchError(async (req, res) => {
  const { code } = req.params;
  const emailCode = await EmailCode.findOne({ where: { code } });
  if (!emailCode) return res.status(401).json({ message: "Invalid Code" });
  const user = await User.findByPk(emailCode.userId);
  user.isVerified = true;
  await user.save();
  await emailCode.destroy();

  return res.json(user);
});

const login = catchError(async (req, res) => {
  const { email, password } = req.body;

  const user = await User.findOne({ where: { email } }); // podemos agregar el isVerified: true acá para validar la validación de correo.
  if (!user)
    return res.status(401).json({ message: "Invalid credentials" });


  const passwordVerification = await bcrypt.compare(
    password,
    user.password
  );
  if (!passwordVerification)
    return res.status(401).json({ message: "Invalid credentials" });

    const accessToken = jwt.sign(
      {user},
      process.env.TOKEN_SECRET,
      {expiresIn: "1d"}     
      )

      const verificatedUser = await user.isVerified == true
      if(!verificatedUser) return res.status(401).json({message: "User account not verified"})
      

  return res.status(201).json({user, accessToken});
});

const getLoggedUser =  catchError(async(req, res) => {
  
  return res.json(req.user);
})

module.exports = {
  getAll,
  create,
  getOne,
  remove,
  update,
  verifyCode,
  login,
  getLoggedUser
};
