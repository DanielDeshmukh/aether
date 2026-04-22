import React from 'react';
import Header from "../components/Header";
import InputUrl from '../components/InputUrl';

const Homepage = () => {

    return (
        <div className="min-h-screen bg-lambo-black font-mono">
            <Header />
            <main className="pt-24 pb-10 px-5 md:px-10 max-w-screen-2xl mx-auto">
                <div className="lg:w-2/3 space-y-8">
                    <InputUrl />
                </div>
            </main>

        </div>
    );
};

export default Homepage;