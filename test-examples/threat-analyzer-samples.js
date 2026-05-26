const analyzer = require('../threat-analyzer');

const samples = [
    {
        name: 'safe email',
        input: 'Hi Sam, the project notes are ready at https://docs.google.com/document/demo. Thanks.'
    },
    {
        name: 'phishing email with urgent words',
        input: 'URGENT: Your account suspended warning requires you to verify now immediately at http://billing.example.com/login.'
    },
    {
        name: 'lookalike PayPal domain',
        input: 'Payment failed. Please review your account at https://paypa1.com/secure/account/update.'
    },
    {
        name: 'shortened suspicious link',
        input: 'Limited time reset required: https://bit.ly/secure-password-reset'
    }
];

samples.forEach((sample) => {
    const result = analyzer.analyzeThreatText(sample.input);
    console.log(`\n${sample.name}`);
    console.log(JSON.stringify(result, null, 2));
});
