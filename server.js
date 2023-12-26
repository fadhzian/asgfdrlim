const express = require('express');
const mongodb = require('mongodb');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const swaggerjsdoc = require("swagger-jsdoc");
const swaggerui = require("swagger-ui-express");
const router = require('express').Router();

const app = express();
const port = process.env.PORT || 4000;
const secretKey = 'your-secret-key';

// MongoDB connection URL
const mongoURL =
  'mongodb+srv://aza:mongoodb@asg3433.c2s3iyk.mongodb.net/?retryWrites=true&w=majority';

// MongoDB database and collections names
const dbName = 'appointment';
const staffCollection = 'staff';
const securityCollection = 'security';
const appointmentCollection = 'appointments';

// Middleware for parsing JSON data
app.use(express.json());

const options = {
    definition: {
        openapi: "3.0.0",
        info: {
            title: "office appointment",
            version: "1.0.0",
            description: "BENRS2 Group 13"
        },
    },
    apis: ['./server.js'],
}

const spacs = swaggerjsdoc(options);
app.use(
    "/api-docs",
    swaggerui.serve,
    swaggerui.setup(spacs)
)

// MongoDB connection
mongodb.MongoClient.connect(mongoURL)
  .then((client) => {
    const db = client.db(dbName);
    const staffDB = db.collection(staffCollection);
    const securityDB = db.collection(securityCollection);
    const appointmentDB = db.collection(appointmentCollection);
    //module.exports = { staffDB, securityDB, appointmentDB };

// Middleware for authentication and authorization
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).send('Missing token');
  }

  jwt.verify(token, secretKey, (err, user) => {
    if (err) {
      return res.status(403).send('Invalid or expired token');
    }
    req.user = user;
    next();
  });
};
// Export authenticateToken middleware
exports.authenticateToken = authenticateToken;

/**
 * @swagger
 * components:
 *   BearerAuth:
 *     type: apiKey
 *     in: header
 *     name: Authorization
 *
 * /register-staff:
 *   post:
 *     summary: Register a new staff member
 *     description: Register a new staff member with a unique username and hashed password.
 *     content:
 *       application/json:
 *         schema:
 *           type: object
 *           properties:
 *             username:
 *               type: string
 *               description: The unique username for the staff member.
 *             password:
 *               type: string
 *               description: The password for the staff member.
 *     responses:
 *       200:
 *         description: Staff registered successfully.
 *       403:
 *         description: Invalid or unauthorized token.
 *       409:
 *         description: Username already exists.
 *       500:
 *         description: Error registering staff.
 */

// Register staff
app.post('/register-staff', authenticateToken, async (req, res) => {
  const { role } = req.user;

  if (role !== 'security') {
    return res.status(403).send('Invalid or unauthorized token');
  }

  const { username, password } = req.body;

  const existingStaff = await staffDB.findOne({ username });

  if (existingStaff) {
    return res.status(409).send('Username already exists');
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  const staff = {
    username,
    password: hashedPassword,
  };

  staffDB
    .insertOne(staff)
    .then(() => {
      res.status(200).send('Staff registered successfully');
    })
    .catch((error) => {
      res.status(500).send('Error registering staff');
    });
});

/**
 * @swagger
 * /register-security:
 *   post:
 *     summary: Register a new security member
 *     description: Register a new security member with a unique username and hashed password.
 *     tags:
 *       - Security
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *                 description: The unique username for the security member.
 *               password:
 *                 type: string
 *                 description: The password for the security member.
 *     responses:
 *       200:
 *         description: Security registered successfully.
 *       409:
 *         description: Username already exists.
 *       500:
 *         description: Error registering security.
 */

// Register security
app.post('/register-security', async (req, res) => {
  const { username, password } = req.body;

  const existingSecurity = await securityDB.findOne({ username });

  if (existingSecurity) {
    return res.status(409).send('Username already exists');
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  const security = {
    username,
    password: hashedPassword,
  };

  securityDB
    .insertOne(security)
    .then(() => {
      res.status(200).send('Security registered successfully');
    })
    .catch((error) => {
      res.status(500).send('Error registering security');
    });
});

/**
 * @swagger
 * /login-staff:
 *   post:
 *     summary: Log in as a staff member
 *     description: Authenticate and generate a token for a staff member based on provided credentials.
 *     tags:
 *       - Staff
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *                 description: The username of the staff member.
 *               password:
 *                 type: string
 *                 description: The password of the staff member.
 *     responses:
 *       200:
 *         description: Login successful. Returns a token.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 token:
 *                   type: string
 *                   description: The authentication token.
 *       401:
 *         description: Invalid credentials.
 *       500:
 *         description: Error storing token.
 */

    // Staff login
app.post('/login-staff', async (req, res) => {
  const { username, password } = req.body;

  const staff = await staffDB.findOne({ username });

  if (!staff) {
    return res.status(401).send('Invalid credentials');
  }

  const passwordMatch = await bcrypt.compare(password, staff.password);

  if (!passwordMatch) {
    return res.status(401).send('Invalid credentials');
  }

  const token = jwt.sign({ username, role: 'staff' }, secretKey);
  staffDB
    .updateOne({ username }, { $set: { token } })
    .then(() => {
      res.status(200).json({ token });
    })
    .catch(() => {
      res.status(500).send('Error storing token');
    });
});

/**
 * @swagger
 * /login-security:
 *   post:
 *     summary: Log in as a security member
 *     description: Authenticate and generate a token for a security member based on provided credentials.
 *     tags:
 *       - Security
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *                 description: The username of the security member.
 *               password:
 *                 type: string
 *                 description: The password of the security member.
 *     responses:
 *       200:
 *         description: Login successful. Returns a token.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 token:
 *                   type: string
 *                   description: The authentication token.
 *       401:
 *         description: Invalid credentials.
 *       500:
 *         description: Error storing token.
 */

    // Security login
    app.post('/login-security', async (req, res) => {
      const { username, password } = req.body;

      const security = await securityDB.findOne({ username });

      if (!security) {
        return res.status(401).send('Invalid credentials');
      }

      const passwordMatch = await bcrypt.compare(password, security.password);

      if (!passwordMatch) {
        return res.status(401).send('Invalid credentials');
      }

      const token = security.token || jwt.sign({ username, role: 'security' }, secretKey);
      securityDB
        .updateOne({ username }, { $set: { token } })
        .then(() => {
          res.status(200).json({ token });
        })
        .catch(() => {
          res.status(500).send('Error storing token');
        });
    });

    /**
 * @swagger
 * /appointments:
 *   post:
 *     summary: Create a new appointment
 *     description: Create a new appointment with the provided details.
 *     tags:
 *       - Appointments
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               name:
 *                 type: string
 *                 description: The name of the appointment.
 *               company:
 *                 type: string
 *                 description: The company associated with the appointment.
 *               purpose:
 *                 type: string
 *                 description: The purpose of the appointment.
 *               phoneNo:
 *                 type: string
 *                 description: The phone number for the appointment.
 *               date:
 *                 type: string
 *                 format: date
 *                 description: The date of the appointment (YYYY-MM-DD).
 *               time:
 *                 type: string
 *                 format: time
 *                 description: The time of the appointment (HH:mm).
 *               verification:
 *                 type: boolean
 *                 description: The verification status of the appointment.
 *               staff:
 *                 type: object
 *                 properties:
 *                   username:
 *                     type: string
 *                     description: The username of the staff member associated with the appointment.
 *     responses:
 *       200:
 *         description: Appointment created successfully.
 *       500:
 *         description: Error creating appointment.
 */

    // Create appointment
    app.post('/appointments', async (req, res) => {
      const {
        name,
        company,
        purpose,
        phoneNo,
        date,
        time,
        verification,
        staff: { username },
      } = req.body;

      const appointment = {
        name,
        company,
        purpose,
        phoneNo,
        date,
        time,
        verification,
        staff: { username },
      };

      appointmentDB
        .insertOne(appointment)
        .then(() => {
          res.status(200).send('Appointment created successfully');
        })
        .catch((error) => {
          res.status(500).send('Error creating appointment');
        });
    });

/**
 * @swagger
 * /staff-appointments/{username}:
 *   get:
 *     summary: Get appointments for a staff member
 *     description: Retrieve appointments associated with a specific staff member.
 *     tags:
 *       - Appointments
 *     parameters:
 *       - in: path
 *         name: username
 *         required: true
 *         schema:
 *           type: string
 *         description: The username of the staff member.
 *     security:
 *       - BearerAuth: []  # Use security definition name if authentication is required
 *     responses:
 *       200:
 *         description: A list of appointments for the specified staff member.
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   name:
 *                     type: string
 *                     description: The name of the appointment.
 *                   company:
 *                     type: string
 *                     description: The company associated with the appointment.
 *                   purpose:
 *                     type: string
 *                     description: The purpose of the appointment.
 *                   phoneNo:
 *                     type: string
 *                     description: The phone number for the appointment.
 *                   date:
 *                     type: string
 *                     format: date
 *                     description: The date of the appointment (YYYY-MM-DD).
 *                   time:
 *                     type: string
 *                     format: time
 *                     description: The time of the appointment (HH:mm).
 *                   verification:
 *                     type: boolean
 *                     description: The verification status of the appointment.
 *                   staff:
 *                     type: object
 *                     properties:
 *                       username:
 *                         type: string
 *                         description: The username of the staff member associated with the appointment.
 *       403:
 *         description: Invalid or unauthorized token.
 *       500:
 *         description: Error retrieving appointments.
 */

// Get staff's appointments
app.get('/staff-appointments/:username', authenticateToken, async (req, res) => {
  const { username } = req.params;
  const { role, username: authenticatedUsername } = req.user;

  if (role !== 'staff') {
    return res.status(403).send('Invalid or unauthorized token');
  }

  if (username !== authenticatedUsername) {
    return res.status(403).send('Invalid or unauthorized token');
  }

  appointmentDB
    .find({ 'staff.username': username })
    .toArray()
    .then((appointments) => {
      res.json(appointments);
    })
    .catch((error) => {
      res.status(500).send('Error retrieving appointments');
    });
});

/**
 * @swagger
 * /appointments/{name}:
 *   put:
 *     summary: Update appointment verification by visitor name
 *     description: Update the verification status of an appointment by visitor name, restricted to staff members.
 *     tags:
 *       - Appointments
 *     parameters:
 *       - in: path
 *         name: name
 *         required: true
 *         schema:
 *           type: string
 *         description: The name of the appointment.
 *       - in: header
 *         name: Authorization
 *         required: true
 *         schema:
 *           type: string
 *         description: Bearer token for authentication.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               verification:
 *                 type: boolean
 *                 description: The updated verification status.
 *     responses:
 *       200:
 *         description: Appointment verification updated successfully.
 *       403:
 *         description: Invalid or unauthorized token.
 *       404:
 *         description: Appointment not found.
 *       500:
 *         description: Error updating appointment verification.
 */

// Update appointment verification by visitor name
app.put('/appointments/:name', authenticateToken, async (req, res) => {
  const { name } = req.params;
  const { verification } = req.body;
  const { role, username: authenticatedUsername } = req.user;

  if (role !== 'staff') {
    return res.status(403).send('Invalid or unauthorized token');
  }

  // Find the appointment by name and staff username
  const appointment = await appointmentDB.findOne({ name, 'staff.username': authenticatedUsername });

  if (!appointment) {
    return res.status(404).send('Appointment not found');
  }

  // Update the verification only if the staff member matches the creator
  appointmentDB
    .updateOne({ name, 'staff.username': authenticatedUsername }, { $set: { verification } })
    .then(() => {
      res.status(200).send('Appointment verification updated successfully');
    })
    .catch((error) => {
      res.status(500).send('Error updating appointment verification');
    });
});

/**
 * @swagger
 * /appointments/{name}:
 *   delete:
 *     summary: Delete appointment by name
 *     description: Delete an appointment by name, restricted to staff members.
 *     tags:
 *       - Appointments
 *     parameters:
 *       - in: path
 *         name: name
 *         required: true
 *         schema:
 *           type: string
 *         description: The name of the appointment.
 *       - in: header
 *         name: Authorization
 *         required: true
 *         schema:
 *           type: string
 *         description: Bearer token for authentication.
 *     responses:
 *       200:
 *         description: Appointment deleted successfully.
 *       403:
 *         description: Invalid or unauthorized token.
 *       500:
 *         description: Error deleting appointment.
 */

    // Delete appointment
    app.delete('/appointments/:name', authenticateToken, async (req, res) => {
      const { name } = req.params;
      const { role } = req.user;
    
      if (role !== 'staff') {
        return res.status(403).send('Invalid or unauthorized token');
      }
    
      appointmentDB
        .deleteOne({ name })
        .then(() => {
          res.status(200).send('Appointment deleted successfully');
        })
        .catch((error) => {
          res.status(500).send('Error deleting appointment');
        });
    });

    /**
 * @swagger
 * /appointments:
 *   get:
 *     summary: Get all appointments (for security)
 *     description: Retrieve all appointments, filtered by name if specified, restricted to security members.
 *     tags:
 *       - Appointments
 *     parameters:
 *       - in: query
 *         name: name
 *         schema:
 *           type: string
 *         description: Optional. Filter appointments by name (case-insensitive).
 *       - in: header
 *         name: Authorization
 *         required: true
 *         schema:
 *           type: string
 *         description: Bearer token for authentication.
 *     responses:
 *       200:
 *         description: An array of appointments.
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 $ref: '#/components/schemas/Appointment'  # Reference to the Appointment schema.
 *       403:
 *         description: Invalid or unauthorized token.
 *       500:
 *         description: Error retrieving appointments.
 */

    // Get all appointments (for security)
    app.get('/appointments', authenticateToken, async (req, res) => {
      const { name } = req.query;
      const { role } = req.user;
    
      if (role !== 'security') {
        return res.status(403).send('Invalid or unauthorized token');
      }
    
      const filter = name ? { name: { $regex: name, $options: 'i' } } : {};
    
      appointmentDB
        .find(filter)
        .toArray()
        .then((appointments) => {
          res.json(appointments);
        })
        .catch((error) => {
          res.status(500).send('Error retrieving appointments');
        });
    });

    /**
 * @swagger
 * /logout:
 *   post:
 *     summary: Logout
 *     description: Logout the user, clearing the token from the database.
 *     tags:
 *       - Authentication
 *     security:
 *       - BearerAuth: []  # Use security definition name if authentication is required
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *                 description: The username of the user to logout.
 *     responses:
 *       200:
 *         description: Logout successful.
 *       403:
 *         description: Invalid or unauthorized token.
 *       500:
 *         description: Error logging out.
 */

// Logout
app.post('/logout', authenticateToken, async (req, res) => {
    const { role } = req.user;
  
    // Depending on the role (staff or security), update the corresponding collection (staffDB or securityDB)
    if (role === 'staff') {
      staffDB
        .updateOne({ username: req.user.username }, { $unset: { token: 1 } })
        .then(() => {
          res.status(200).send('Logged out successfully');
        })
        .catch(() => {
          res.status(500).send('Error logging out');
        });
    } else if (role === 'security') {
      securityDB
        .updateOne({ username: req.user.username }, { $unset: { token: 1 } })
        .then(() => {
          res.status(200).send('Logged out successfully');
        })
        .catch(() => {
          res.status(500).send('Error logging out');
        });
    } else {
      res.status(500).send('Invalid role');
    }
  });
  
    // Start the server
    app.listen(port, () => {
      console.log(`Server is running on port ${port}`);
    });
  })
  .catch((error) => {
    console.log('Error connecting to MongoDB:', error);
  });