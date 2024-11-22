const bcrypt = require('bcrypt');

async function hashPassword(password) {
    let hashedPassword
    try {
        const salt = await bcrypt.genSalt(10);
        hashedPassword = await bcrypt.hash(password, salt);

        console.log('Password: ', password);
        console.log('Salt: ', salt);
        console.log('Hashed Password: ', hashedPassword);
    } catch (error) {
        console.error('Error: ', error);
    }

    return hashedPassword;
}

async function comparePassword(inputPassword, hashedPassword) {

    try {
        const isMatch = await bcrypt.compare(inputPassword, hashedPassword);

        if (isMatch) {
            console.log('Password is correct.');
        } else {
            console.log('Password is incorrect.');
        }
    } catch (error) {
        console.error('Error:', error);
    }
}

async function main() {
    const password = 'salasana123'
    // const hashedPassword = await hashPassword(password);

    const salt = bcrypt.genSaltSync(10);
    const hashedPassword = bcrypt.hashSync(password, salt);

    await comparePassword(password, hashedPassword);
}

main();