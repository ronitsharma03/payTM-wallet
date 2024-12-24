import { useEffect, useState } from "react"

export const Toast = ({message}: {message: string}) => {
    const [property, setProperty] = useState("block");
    useEffect(() => {
        setTimeout(() => {
            setProperty("");
        }, 2000);
    }, []);

    return (
        <div className={`absolute bottom-2 right-2 ${property}`}>
            <div className="bg-zinc-600 color-white">
                {message}
            </div>
        </div>
    )
}