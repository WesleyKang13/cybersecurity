export default function ApplicationLogo(props) {
    return (
        <img
            {...props}
            src="/images/logo.png"
            alt="Logo"
            className={`w-auto h-20 ${props.className}`}
        />
    );
}
