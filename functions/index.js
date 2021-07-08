/* eslint-disable max-len */
const functions = require("firebase-functions");
const admin = require("firebase-admin");

// Get the `FieldValue` object
admin.initializeApp();

// async function setRole(email, role) {
//     const user = await admin.auth().getUserByEmail(email); // 1
//     if (user.customClaims && user.customClaims.admin === true) {
//         return;
//     } else if(user.customClaims && user.customClaims.staff == true) {
//         return;
//     }
//     return admin.auth().setCustomUserClaims(user.uid, {
//         [role]: true
//     }); // 3
// }

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
