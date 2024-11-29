# 🏠 **Realty Company Web Application**

This web application is a property management tool designed for realty companies. It allows realtors to manage and view property details, including tenant information, images, related files, and more. Users can log in to access the full management system, or browse available properties without making any changes.

---

## 🌟 **Features**

- **Property Management**: View detailed information about properties, including location, price, and availability.
- **Tenant Details**: See who is renting the property, with additional contact details and rental history.
- **Images & Files**: View images and related documents for each property.
- **User Roles**: 
  - **Admin/Realty Company Staff**: Full access to manage and edit property details.
  - **Guest/User**: Limited access to view properties and their details, without the ability to make changes.
- **Login System**: Only authenticated users (admins or realty staff) can edit property information. Guests can browse without logging in.

---

## 🛠️ **Tech Stack**

- **Frontend**: HTML, CSS, JavaScript  
- **Backend**: Python, Flask  
- **Database**: SQLite (or any other relational database depending on your implementation)

---

## 🚀 **Getting Started**

### 1. Clone the repository:
```bash
git clone https://github.com/your-username/realty-company.git
cd realty-company
```

### 2. Install dependencies:
```bash
pip install -r requirements.txt
```

### 3. Run the Flask application:
```bash
python app.py
```

### 4. Open your browser and navigate to `http://127.0.0.1:5000/`.

---

## 🛠️ **Key Components**

- **Login System**: Users must log in to access management features. If not logged in, they can only view property details.
- **Property Listing**: Displays a list of properties along with their details such as rent price, area, and availability status.
- **Image Gallery**: Property images are displayed to provide better visual context for each listing.
- **File Attachments**: Allows admins to upload files (e.g., contracts, floor plans) related to each property.

---

## 🤝 **Contributions**

Feel free to fork the repository and submit pull requests. I welcome feedback and contributions to improve the project!
