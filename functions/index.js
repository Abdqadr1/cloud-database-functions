/* eslint-disable max-len */
const functions = require("firebase-functions");
const admin = require("firebase-admin");
const algorithm = require("aes256");
// const eccrypto = require("eccrypto");
const crypto = require("crypto");

// Get the `FieldValue` object
admin.initializeApp();

const keys = admin.firestore().collection("keys");
const staffs = admin.firestore().collection("staffs");
const admins = admin.firestore().collection("admins");
const students = admin.firestore().collection("students");
const thesisCollection = admin.firestore().collection("thesis");


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
  }).catch(() => {
    throw new functions.https.HttpsError("aborted", "error occurred while deleting user");
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

  const userKeys = crypto.createECDH("secp256k1");
  userKeys.generateKeys();
  const privateKey = userKeys.getPrivateKey().toString("base64");
  const publicKey = userKeys.getPublicKey().toString("base64");

  await keys.doc(data.uid).set({"private_key": privateKey});

  if (data.which == "student") {
    const studentRecord = {
      "matric": data.matric,
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
  if (data.which == "staff" || data.which == "admin") {
    const staffRecord = {
      "staff_id": data.staff_id,
      "name": encryptData(data.name, publicKey),
      "email": encryptData(data.email, publicKey),
      "phone": encryptData(data.phone_no, publicKey),
      "title": encryptData(data.title, publicKey),
      "office_address": encryptData(data.office_address, publicKey),
      "public_key": publicKey,
    };
    if (data.which == "staff") {
      staffRecord.dept = encryptData(data.dept, publicKey);
      await staffs.doc(uid).set(staffRecord);
      await admin.auth().setCustomUserClaims(uid, {
        [data.which]: true,
      });
    }
    if (data.which == "admin") {
      await admins.doc(uid).set(staffRecord);
      await admin.auth().setCustomUserClaims(uid, {
        [data.which]: true,
      });
    }
    return {
      message: `Request fulfilled! ${data.email} is now a
                ${data.which}.`,
    };
  }
});

exports.getUserDocument = functions.https.onCall(async (data, context) => {
  if (!context || !context.auth.uid) {
    throw new functions.https.HttpsError("unauthenticated", "You are not authenticated to perform this action");
  }
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
  if (which == "admin") {
    const adminRecord = await admins.doc(id).get();
    if (!adminRecord.exists) {
      throw new functions.https.HttpsError("not-found", "Record does not exist");
    } else {
      return decryptRecord(adminRecord.data());
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
  const thesis = await thesisCollection.doc(id).get();
  if (!thesis.exists) {
    throw new functions.https.HttpsError("not-found", "Record does not exist");
  } else {
    // still have work to do here. whose key are we using to decrypt.
    return decryptRecord(thesis.data());
  }
});

exports.registerThesis = functions.https.onCall(async (data, context) => {
  if (!context || !context.auth.uid) {
    throw new functions.https.HttpsError("unauthenticated", "You are not authenticated to perform this action");
  }
  const id = data.uid;
  const author = await students.doc(id).get();
  const authorData = author.data();
  const thesisData = {
    "title": encryptData(data.title, authorData["public_key"]),
    "author": encryptData(data.author, authorData["public_key"]),
    "content": encryptData(data.content, authorData["public_key"]),
  };
  await thesisCollection.doc(id).set(thesisData);
  return {
    "message": "Thesis added successfully",
  };
});

exports.getStudentDocument = functions.https.onCall(async (data, context) => {
  if (!context || !context.auth.uid) {
    throw new functions.https.HttpsError("unauthenticated", "You are not authenticated to perform this action");
  }
  const matric = data.matric;
  if (!matric || matric.length == 0) {
    throw new functions.https.HttpsError("invalid-argument", "Enter a matric number to search for");
  }
  const studentRecord = await students.where("matric", "==", data.matric.toUpperCase()).limit(1).get();
  if (studentRecord.size() == 1) {
    return decryptRecord(studentRecord.data());
  } else {
    throw new functions.https.HttpsError("not-found", "No student with " + data.matric.toUpperCase() + " found");
  }
});

exports.createThesisRecord = functions.https.onCall(async (data, context) => {
  if (!context.auth && context.auth.token.admin !== true) {
    throw new functions.https.HttpsError("unauthenticated", "You are not authenticated to perform this action");
  }
  const which = data.which;
  const uid = data.uploaded_by;
  if (which == "admin") {
    const userRecord = await admins.doc(uid).get();
    if (userRecord.exists) {
      const user = decryptRecord(userRecord.data());
      const key = userRecord.data().public_key;
      const thesisRecord = {
        "author_name": encryptData(data.author_name, key),
        "author_matric": encryptData(data.author_matric, key),
        "title": encryptData(data.title, key),
        "uri": encryptData(data.uri, key),
        "uploaded_by": encryptData(data.uploaded_by, key),
        "uploaded_by_id": user.staff_id,
        "public_key": key,
      };
      const res = await thesisCollection.add(thesisRecord);
      return {
        message: `thesis record created, ${res.id}`,
      };
    } else {
      throw new functions.https.HttpsError("not-found", "Admin not found by that uid");
    }
  }

  if (which == "student") {
    const userRecord = await students.doc(uid).get();
    if (userRecord.exists) {
      const user = decryptRecord(userRecord.data());
      const key = userRecord.data().public_key;
      const thesisRecord = {
        "author_name": encryptData(data.author_name, key),
        "author_matric": encryptData(data.author_matric, key),
        "title": encryptData(data.title, key),
        "uri": encryptData(data.uri, key),
        "uploaded_by": encryptData(data.uploaded_by, key),
        "uploaded_by_id": user.matric,
        "public_key": key,
      };
      const res = await thesisCollection.add(thesisRecord);
      return {
        message: `thesis record created, ${res.id}`,
      };
    } else {
      throw new functions.https.HttpsError("not-found", "Admin not found by that uid");
    }
  }
});

exports.getThesis = functions.https.onCall(async (data, context) => {
  if (!context.auth && !context.auth.uid) {
    throw new functions.https.HttpsError("unauthenticated", "You are not authenticated to perform this action");
  }
  const thesis = [];
  const uid = data.uid;
  // const which = data.which;
  const snapshot = await thesisCollection.where("uploaded_by_id", "==", uid).get();
  const list = snapshot.docs;
  if (list.length > 0) {
    list.forEach((document) => {
      // const id = document.id;
      const dataEn = document.data();
      const record = decryptThesisRecord(dataEn);
      thesis.push(record);
    });
  }
  return {thesis};
});

const encryptData = (data, key) => {
  const encrypted = algorithm.encrypt(key, data);
  return encrypted;
};

const decryptData = (encrypt, key) => {
  const decrypted = algorithm.decrypt(key, encrypt);
  return decrypted;
};

const decryptRecord = (record) => {
  const key = record["public_key"];
  console.log("public_key", key);
  const newObj = {};
  // eslint-disable-next-line guard-for-in
  for (const prop in record) {
    if (prop !== "public_key" && prop !== "matric" && prop !== "staff_id" && prop !== "uploaded_by_id") {
      newObj[prop] = decryptData(record[prop], key);
    }
    if (prop == "matric" || prop == "staff_id" || prop == "uploaded_by_id") {
      newObj[prop] = record[prop];
    }
  }
  return newObj;
};

const decryptThesisRecord = (thesis) => {
  const key = thesis.public_key;
  const newObj = {};
  for (const prop in thesis) {
    if (Object.prototype.hasOwnProperty.call(thesis, prop)) {
      if (prop !== "public_key" && prop !== "uploaded_by_id") {
        newObj[prop] = decryptData(thesis[prop], key);
      }
      if (prop == "uploaded_by_id") {
        newObj[prop] = thesis[prop];
      }
    } else {
      throw new functions.https.HttpsError("not-found", `"property" ${prop} not found`);
    }
  }
  return newObj;
};
