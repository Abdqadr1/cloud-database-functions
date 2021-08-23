/* eslint-disable max-len */
const functions = require("firebase-functions");
const admin = require("firebase-admin");
// const eccrypto = require("eccrypto");
const crypto = require("crypto");

// Get the `FieldValue` object
admin.initializeApp();


exports.addCustomClaims = functions.https.onCall((data, context) => {
  // Checking that the user is authenticated.
  if (!context.auth) {
    // Throwing an HttpsError so that the client gets the error details.
    throw new functions.https.HttpsError("failed-precondition", "The function must be called " +
        "while authenticated.");
  }

  if (!(data.which == "staff" || data.which == admin)) {
    // Throwing an HttpsError so that the client gets the error details.
    throw new functions.https.HttpsError("permission-denied", "You have to be a staff or admin to perform this action");
  }
  const uid = data.uid;
  const role = data.role;
  const value = data.value;
  const email = data.email;

  if (!(typeof(uid) === "string") || uid.length === 0) {
    // Throwing an HttpsError so that the client gets the error details.
    throw new functions.https.HttpsError("invalid-argument', 'The function must be called " +
        "with a user id.");
  }

  if (!(typeof(role) === "string") || role.length === 0) {
    // Throwing an HttpsError so that the client gets the error details.
    throw new functions.https.HttpsError("invalid-argument", "The function must be called " +
        "with a role.");
  }

  if (!(typeof(email) === "string") || email.length === 0) {
    // Throwing an HttpsError so that the client gets the error details.
    throw new functions.https.HttpsError("invalid-argument", "The function must be called " +
        "with a user email.");
  }

  if (!(typeof(value) === "boolean")) {
    // Throwing an HttpsError so that the client gets the error details.
    throw new functions.https.HttpsError("invalid-argument", "The function must be called " +
        "with a boolean value.");
  }


  return admin.auth().setCustomUserClaims(uid, {
    [role]: value,
  }).then(() => {
    return {
      message: `Request fulfilled! ${email} is now a
                ${role}.`,
    };
  });
});

exports.deleteUser = functions.https.onCall((data, context) => {
  if (!context.auth && context.auth.token.admin !== true) {
    throw new functions.https.HttpsError("unauthenticated", "You are not authenticated to perform this action");
  }

  const uid = data.uid;
  if (!(typeof (uid) === "string") || uid.length === 0) {
    throw new functions.https.HttpsError("invalid-argument", "Function must be called with a valid user id");
  }

  admin.auth().deleteUser(uid).then(() => {
    return {
      message: "User deleted",
    };
  }).catch((error) => {
    return {
      message: "Error deleting user" + error,
    };
  });
});

exports.createUserRecord = functions.https.onCall(async (data, context) => {
  if (!context.auth) {
    throw new functions.https.HttpsError("unauthenticated", "You are not authenticated to perform this action");
  }
  const uid = data.uid;
  if (!(typeof (uid) === "string") || uid.length === 0) {
    throw new functions.https.HttpsError("invalid-argument", "Function must be called with a valid user id");
  }
  const keys = admin.firestore().collection("keys");
  const staffs = admin.firestore().collection("staffs");
  const students = admin.firestore().collection("students");

  const userKeys = crypto.createECDH("secp256k1");
  userKeys.generateKeys();
  const privateKey = userKeys.getPrivateKey().toString("base64");
  const publicKey = userKeys.getPublicKey().toString("base64");

  await keys.doc(data.uid).set({"private_key": privateKey});

  if (data.which == "student") {
    const studentRecord = {
      "matric": encryptData(data.matric, publicKey),
      "name": encryptData(data.name, publicKey),
      "email": encryptData(data.email, publicKey),
      "phone": encryptData(data.phone, publicKey),
      "address": encryptData(data.address, publicKey),
      "program": encryptData(data.program, publicKey),
      "year_of_award": encryptData(data.year_of_award, publicKey),
      "dob": encryptData(data.dob, publicKey),
      "public_key": publicKey,
    };
    await students.doc(uid).set(studentRecord);
    return {
      message: ` ${data.email} record is added`,
    };
  }
  if (data.which == "staff") {
    const staffRecord = {
      "staff_id": encryptData(data.staff_id, publicKey),
      "name": encryptData(data.name, publicKey),
      "email": encryptData(data.email, publicKey),
      "phone": encryptData(data.phone_no, publicKey),
      "title": encryptData(data.title, publicKey),
      "office_address": encryptData(data.office_address, publicKey),
      "dept": encryptData(data.dept, publicKey),
      "public_key": publicKey,
    };
    await staffs.doc(uid).set(staffRecord);
    const role = data.role;
    const value = data.value;
    await admin.auth().setCustomUserClaims(uid, {
      [role]: value,
    });
    return {
      message: `Request fulfilled! ${data.email} is now a
                ${role}.`,
    };
  }
});

exports.getUserDocument = functions.https.onCall(async (data, context) => {
  if (!context || !context.auth.uid) {
    throw new functions.https.HttpsError("unauthenticated", "You are not authenticated to perform this action");
  }
  const staffs = admin.firestore().collection("staffs");
  const students = admin.firestore().collection("students");
  const id = data.uid;
  const which = data.which;
  if (which == "staff") {
    const staffRecord = await staffs.doc(id).get();
    if (!staffRecord.exists) {
      throw new functions.https.HttpsError("not-found", "Record does not exist");
    } else {
      return decryptRecord(staffRecord.data());
    }
  }
  if (which == "student") {
    const studentRecord = await students.doc(id).get();
    if (!studentRecord.exists) {
      throw new functions.https.HttpsError("not-found", "Record does not exist");
    } else {
      return decryptRecord(studentRecord.data());
    }
  }
});

exports.getStudentThesis = functions.https.onCall(async (data, context) => {
  if (!context || !context.auth.uid) {
    throw new functions.https.HttpsError("unauthenticated", "You are not authenticated to perform this action");
  }
  const id = data.uid;
  const thesisCollection = admin.firestore().collection("thesis");
  const thesis = await thesisCollection.doc(id).get();
  if (!thesis.exists) {
    throw new functions.https.HttpsError("not-found", "Record does not exist");
  } else {
    // still have work to do here. whose key are we using to decrypt.
    return decryptRecord(thesis.data());
  }
});

const encryptData = (data, key) => {
  const algorithm = require("aes256");
  const encrypted = algorithm.encrypt(key, data);
  return encrypted;
};

const decryptData = (encrypt, key) => {
  const algorithm = require("aes256");
  const decrypted = algorithm.decrypt(key, encrypt);
  return decrypted;
};

const decryptRecord = (record) => {
  const key = record["public_key"];
  const newObj = {};
  for (const prop in record) {
    if (prop !== "public_key") {
      newObj[prop] = decryptData(record[prop], key);
    }
  }
  return newObj;
};
